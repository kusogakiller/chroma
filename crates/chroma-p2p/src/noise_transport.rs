//! Noise XX transport wiring for P2P connections.
//!
//! Responsibilities of this module (and nothing else):
//! - async XX handshake over a TCP stream (framed, bounded, deadline-driven)
//! - length-prefixed encrypted chunk framing for the session
//! - [`NoiseReader`] (`AsyncRead` over decrypted bytes) and [`NoiseWriter`]
//!   (chunked encrypted sends), sharing one [`NoiseSession`]
//!
//! Deliberately OUT of scope here (handled by existing layers unchanged):
//! - application Version/VerAck handshake and network-magic isolation
//!   (see `Node::handle_connection`; network magic is NOT mixed into Noise)
//! - peer scoring, bans, connection caps (see `peer.rs`)
//! - transaction/block validation (see mempool/consensus)
//!
//! Concurrency: [`snow::TransportState`] needs `&mut` for both directions.
//! Reads and writes run on different tasks, so the session lives behind a
//! single `std::sync::Mutex`. Critical sections are microseconds of ChaChaPoly
//! with no `.await` inside, so there is no deadlock or executor stall risk.
//! A poisoned mutex fails closed (I/O error → connection dropped).

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use chroma_crypto::noise::{HandshakeRole, NoiseTransport};

/// Suite assertion: the transport layer pins exactly this suite.
/// If `chroma_crypto` ever changes it, this test fails loudly instead of
/// silently negotiating something else.
#[cfg(test)]
const EXPECTED_SUITE: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Deadline for a full Noise handshake (all three messages).
pub const NOISE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound for one handshake message body (real XX messages with empty
/// payloads are well under 200 bytes; this is pure headroom).
pub const NOISE_HANDSHAKE_MSG_CAP: usize = 2048;
/// Upper bound for one encrypted transport frame on the wire.
pub const NOISE_FRAME_LEN_MAX: usize = 65_535;
/// Plaintext bytes per transport chunk (fits comfortably in one snow
/// message with room for the 16-byte tag).
pub const NOISE_PLAINTEXT_CHUNK: usize = 32_768;

/// Handshake failure. Display strings are static — key material, static
/// public keys, and message contents never appear in errors/logs.
#[derive(Debug)]
pub enum HandshakeError {
    Io(io::Error),
    Timeout,
    Crypto(&'static str),
    Framing(&'static str),
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::Io(e) => write!(f, "noise handshake io: {}", e.kind()),
            HandshakeError::Timeout => write!(f, "noise handshake timed out"),
            HandshakeError::Crypto(m) => write!(f, "noise handshake crypto: {}", m),
            HandshakeError::Framing(m) => write!(f, "noise handshake framing: {}", m),
        }
    }
}

impl std::error::Error for HandshakeError {}

impl From<io::Error> for HandshakeError {
    fn from(e: io::Error) -> Self {
        HandshakeError::Io(e)
    }
}

fn remaining(deadline: Instant) -> Result<Duration, HandshakeError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(HandshakeError::Timeout)
}

/// Read exactly `buf.len()` bytes before `deadline`.
async fn read_exact_deadline<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<(), HandshakeError> {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(remaining(deadline)?, reader.read_exact(buf))
        .await
        .map_err(|_| HandshakeError::Timeout)?
        .map(|_| ())
        .map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                HandshakeError::Framing("unexpected EOF during handshake")
            } else {
                HandshakeError::Io(e)
            }
        })
}

/// Write all bytes before `deadline` (a stalled peer must not park us here).
async fn write_all_deadline<W: AsyncWrite + Unpin>(
    writer: &mut W,
    buf: &[u8],
    deadline: Instant,
) -> Result<(), HandshakeError> {
    tokio::time::timeout(remaining(deadline)?, writer.write_all(buf))
        .await
        .map_err(|_| HandshakeError::Timeout)?
        .map_err(HandshakeError::Io)
}

/// Read one u16-length-prefixed handshake message, bounded by
/// NOISE_HANDSHAKE_MSG_CAP. Zero-length messages are rejected: XX never
/// emits them, so they indicate a broken or hostile peer.
async fn read_hs_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    deadline: Instant,
) -> Result<Vec<u8>, HandshakeError> {
    let mut len_buf = [0u8; 2];
    read_exact_deadline(reader, &mut len_buf, deadline).await?;
    let len = u16::from_le_bytes(len_buf) as usize;
    if len == 0 || len > NOISE_HANDSHAKE_MSG_CAP {
        return Err(HandshakeError::Framing("bad handshake frame length"));
    }
    let mut buf = vec![0u8; len];
    read_exact_deadline(reader, &mut buf, deadline).await?;
    Ok(buf)
}

async fn write_hs_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &[u8],
    deadline: Instant,
) -> Result<(), HandshakeError> {
    if msg.is_empty() || msg.len() > NOISE_HANDSHAKE_MSG_CAP {
        return Err(HandshakeError::Framing("bad handshake frame length"));
    }
    let len = (msg.len() as u16).to_le_bytes();
    write_all_deadline(writer, &len, deadline).await?;
    write_all_deadline(writer, msg, deadline).await?;
    writer.flush().await.map_err(HandshakeError::Io)?;
    Ok(())
}

/// Run the Noise XX handshake over an established TCP stream.
///
/// - `role`: outbound dialer = Initiator, inbound listener = Responder.
/// - `static_key`: this node's long-term identity scalar (used immediately,
///   never stored or logged here).
/// - `deadline`: total bound for all three messages (DoS bound).
///
/// Returns the session plus the peer's static public key (32 bytes) for
/// TOFU binding by the caller. Any failure drops the connection — there is
/// no plaintext fallback at this layer by construction (this function has
/// no plaintext path at all).
pub async fn do_noise_handshake<R, W>(
    reader: &mut R,
    writer: &mut W,
    role: HandshakeRole,
    static_key: &[u8; 32],
    deadline: Instant,
) -> Result<(NoiseSession, [u8; 32]), HandshakeError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use snow::Builder;
    let params = chroma_crypto::noise::NOISE_PARAMS
        .parse()
        .map_err(|_| HandshakeError::Crypto("bad noise params"))?;
    let builder = Builder::new(params);
    // 512-byte scratch: XX handshake messages with empty payloads are tiny.
    let mut scratch = vec![0u8; 512];

    match role {
        HandshakeRole::Initiator => {
            let mut hs = builder
                .local_private_key(static_key)
                .build_initiator()
                .map_err(|_| HandshakeError::Crypto("initiate"))?;
            let n = hs
                .write_message(&[], &mut scratch)
                .map_err(|_| HandshakeError::Crypto("write e"))?;
            write_hs_frame(writer, &scratch[..n], deadline).await?;
            let m2 = read_hs_frame(reader, deadline).await?;
            hs.read_message(&m2, &mut scratch)
                .map_err(|_| HandshakeError::Crypto("read ee"))?;
            let n = hs
                .write_message(&[], &mut scratch)
                .map_err(|_| HandshakeError::Crypto("write se"))?;
            write_hs_frame(writer, &scratch[..n], deadline).await?;
            finish_session(hs)
        }
        HandshakeRole::Responder => {
            let mut hs = builder
                .local_private_key(static_key)
                .build_responder()
                .map_err(|_| HandshakeError::Crypto("respond"))?;
            let m1 = read_hs_frame(reader, deadline).await?;
            hs.read_message(&m1, &mut scratch)
                .map_err(|_| HandshakeError::Crypto("read e"))?;
            let n = hs
                .write_message(&[], &mut scratch)
                .map_err(|_| HandshakeError::Crypto("write ee"))?;
            write_hs_frame(writer, &scratch[..n], deadline).await?;
            let m3 = read_hs_frame(reader, deadline).await?;
            hs.read_message(&m3, &mut scratch)
                .map_err(|_| HandshakeError::Crypto("read se"))?;
            finish_session(hs)
        }
    }
}

fn finish_session(hs: snow::HandshakeState) -> Result<(NoiseSession, [u8; 32]), HandshakeError> {
    let transport =
        NoiseTransport::from_handshake(hs).map_err(|_| HandshakeError::Crypto("transport"))?;
    let remote = transport
        .get_remote_static_key()
        .filter(|k| k.len() == 32)
        .ok_or(HandshakeError::Crypto("missing remote static"))?;
    let mut remote_static = [0u8; 32];
    remote_static.copy_from_slice(remote);
    Ok((NoiseSession::new(transport, remote_static), remote_static))
}

/// An established Noise session shared by one reader and one writer.
///
/// Cloneable handle over `Arc<Mutex<...>>`: the read task and the write task
/// each hold a clone. Critical sections contain only microseconds of
/// ChaChaPoly with no `.await`, so executor stalls and deadlocks are
/// impossible; a poisoned mutex fails closed.
#[derive(Clone)]
pub struct NoiseSession {
    inner: Arc<Mutex<SessionInner>>,
}

struct SessionInner {
    transport: NoiseTransport,
    remote_static: [u8; 32],
}

impl NoiseSession {
    fn new(transport: NoiseTransport, remote_static: [u8; 32]) -> Self {
        NoiseSession {
            inner: Arc::new(Mutex::new(SessionInner {
                transport,
                remote_static,
            })),
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, SessionInner>, io::Error> {
        self.inner
            .lock()
            .map_err(|_| io::Error::other("noise session poisoned"))
    }

    /// Transport messages encrypted so far (soak observability; also
    /// proves rekey boundaries were crossed in long-session tests).
    pub fn sent_count(&self) -> u64 {
        self.lock().map(|s| s.transport.sent_count()).unwrap_or(0)
    }

    /// Transport messages decrypted so far.
    pub fn received_count(&self) -> u64 {
        self.lock()
            .map(|s| s.transport.received_count())
            .unwrap_or(0)
    }

    /// The peer's static public key from the handshake (TOFU binding).
    pub fn remote_static(&self) -> [u8; 32] {
        // Infallible stripe: poisoning here would only hide identity, and
        // every IO path re-locks fallibly. Copy under a best-effort lock.
        self.lock().map(|s| s.remote_static).unwrap_or([0u8; 32])
    }

    /// Encrypt one chunk (caller chunks to NOISE_PLAINTEXT_CHUNK).
    pub fn encrypt_chunk(&self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let mut s = self.lock()?;
        s.transport.encrypt(plaintext).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("noise encrypt: {}", e))
        })
    }

    /// Decrypt one transport message.
    pub fn decrypt_chunk(&self, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        let mut s = self.lock()?;
        s.transport.decrypt(ciphertext).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("noise decrypt: {}", e))
        })
    }
}

/// AsyncRead over decrypted Noise stream bytes.
///
/// Wire format per chunk: `u32 LE ciphertext-length || ciphertext`.
/// Length is validated (1..=NOISE_FRAME_LEN_MAX) BEFORE allocating the
/// exact buffer, so a malicious length cannot trigger a huge allocation.
/// Decryption failures, empty plaintexts, and mid-frame EOFs are hard
/// errors: the connection must be dropped, never retried as plaintext.
pub struct NoiseReader<R> {
    inner: R,
    session: NoiseSession,
    backlog: Vec<u8>,
    backpos: usize,
    // In-progress frame assembly (plain fields: no borrow juggling).
    len_buf: [u8; 4],
    len_pos: usize,
    body: Vec<u8>,
    body_pos: usize,
    body_need: usize,
}

impl<R> NoiseReader<R> {
    /// Borrow the underlying session (counter inspection in tests).
    pub fn session(&self) -> &NoiseSession {
        &self.session
    }

    pub fn new(inner: R, session: NoiseSession) -> Self {
        NoiseReader {
            inner,
            session,
            backlog: Vec::new(),
            backpos: 0,
            len_buf: [0u8; 4],
            len_pos: 0,
            body: Vec::new(),
            body_pos: 0,
            body_need: 0,
        }
    }
}

fn invalid_data(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn unexpected_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "noise frame truncated")
}

impl<R: AsyncRead + Unpin> AsyncRead for NoiseReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.backpos < this.backlog.len() {
            let avail = this.backlog.len() - this.backpos;
            let n = avail.min(buf.remaining());
            buf.put_slice(&this.backlog[this.backpos..this.backpos + n]);
            this.backpos += n;
            if this.backpos >= this.backlog.len() {
                this.backlog.clear();
                this.backpos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.body_need == 0 {
                let mut rb = ReadBuf::new(&mut this.len_buf[this.len_pos..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            if this.len_pos == 0 {
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Ready(Err(unexpected_eof()));
                        }
                        this.len_pos += n;
                        if this.len_pos < 4 {
                            continue;
                        }
                        let len = u32::from_le_bytes(this.len_buf) as usize;
                        if len == 0 || len > NOISE_FRAME_LEN_MAX {
                            return Poll::Ready(Err(invalid_data("bad noise frame length")));
                        }
                        this.body = vec![0u8; len];
                        this.body_pos = 0;
                        this.body_need = len;
                        this.len_pos = 0;
                    }
                }
            } else {
                let need = this.body_need;
                let pos = this.body_pos;
                let mut rb = ReadBuf::new(&mut this.body[pos..need]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(unexpected_eof()));
                        }
                        this.body_pos += n;
                        if this.body_pos < this.body_need {
                            continue;
                        }
                        let ct = std::mem::take(&mut this.body);
                        this.body_need = 0;
                        this.body_pos = 0;
                        match this.session.decrypt_chunk(&ct) {
                            Ok(pt) => {
                                if pt.is_empty() {
                                    // Our writer never emits empty
                                    // plaintexts; treat as protocol error
                                    // (also prevents an EOF-confusion loop).
                                    return Poll::Ready(Err(invalid_data("empty noise plaintext")));
                                }
                                this.backlog = pt;
                                this.backpos = 0;
                            }
                            Err(e) => return Poll::Ready(Err(e)),
                        }
                    }
                }
            }
            if this.backpos < this.backlog.len() {
                let avail = this.backlog.len() - this.backpos;
                let n = avail.min(buf.remaining());
                buf.put_slice(&this.backlog[this.backpos..this.backpos + n]);
                this.backpos += n;
                if this.backpos >= this.backlog.len() {
                    this.backlog.clear();
                    this.backpos = 0;
                }
                return Poll::Ready(Ok(()));
            }
        }
    }
}

/// Connection writer: plaintext (explicit opt-in only) or Noise-encrypted.
/// Both variants preserve the same bounded queue semantics upstream: the
/// write task drops the peer when the 64-slot channel overflows, and slow
/// peers never block other peers. There is deliberately no negotiation
/// between variants, so no downgrade oracle exists.
pub enum NetWriter {
    Plain(tokio::net::tcp::OwnedWriteHalf),
    Secure(NoiseWriter<tokio::net::tcp::OwnedWriteHalf>),
}

impl NetWriter {
    /// Deliver one application frame. Fails closed on encrypt or I/O error.
    pub async fn send(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            NetWriter::Plain(w) => {
                use tokio::io::AsyncWriteExt;
                w.write_all(data).await
            }
            NetWriter::Secure(w) => w.send(data).await,
        }
    }
}

/// Encrypted writer half: chunks plaintext, encrypts each chunk, frames
/// with u32 LE length, and delivers over any AsyncWrite.
pub struct NoiseWriter<W> {
    inner: W,
    session: NoiseSession,
}

impl<W> NoiseWriter<W> {
    pub fn new(inner: W, session: NoiseSession) -> Self {
        NoiseWriter { inner, session }
    }

    /// Borrow the underlying session (counter inspection in tests).
    pub fn session(&self) -> &NoiseSession {
        &self.session
    }

    /// Send plaintext bytes as one or more encrypted frames.
    /// Empty input sends nothing (preserving the no-empty-frames invariant).
    pub async fn send(&mut self, plaintext: &[u8]) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        if plaintext.is_empty() {
            return Ok(());
        }
        for chunk in plaintext.chunks(crate::noise_transport::NOISE_PLAINTEXT_CHUNK) {
            let ct = self.session.encrypt_chunk(chunk)?;
            let len = ct.len() as u32;
            self.inner.write_all(&len.to_le_bytes()).await?;
            self.inner.write_all(&ct).await?;
        }
        self.inner.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    type DuplexReader = NoiseReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>;
    type DuplexWriter = NoiseWriter<tokio::io::WriteHalf<tokio::io::DuplexStream>>;

    fn test_keys() -> ([u8; 32], [u8; 32]) {
        ([0xAAu8; 32], [0xBBu8; 32])
    }

    /// Establish a session pair over an in-memory duplex transport and wrap
    /// both ends in reader/writer adapters.
    async fn duplex_sessions(
        k1: [u8; 32],
        k2: [u8; 32],
    ) -> ((DuplexReader, DuplexWriter), (DuplexReader, DuplexWriter)) {
        let (a, b) = tokio::io::duplex(1 << 20);
        let (mut ar, mut aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);
        let deadline = Instant::now() + Duration::from_secs(10);
        let (r1, r2) = tokio::join!(
            do_noise_handshake(&mut ar, &mut aw, HandshakeRole::Initiator, &k1, deadline),
            do_noise_handshake(&mut br, &mut bw, HandshakeRole::Responder, &k2, deadline)
        );
        let (s1, remote1) = r1.unwrap();
        let (s2, remote2) = r2.unwrap();
        // Cross-identity binding: each side sees the other's static key.
        assert_eq!(
            remote1,
            chroma_crypto::noise::x25519_public_from_private(&k2)
        );
        assert_eq!(
            remote2,
            chroma_crypto::noise::x25519_public_from_private(&k1)
        );
        (
            (NoiseReader::new(ar, s1.clone()), NoiseWriter::new(aw, s1)),
            (NoiseReader::new(br, s2.clone()), NoiseWriter::new(bw, s2)),
        )
    }

    #[test]
    fn test_suite_pinned() {
        assert_eq!(
            chroma_crypto::noise::NOISE_PARAMS,
            EXPECTED_SUITE,
            "transport suite must stay Noise_XX_25519_ChaChaPoly_BLAKE2s"
        );
    }

    #[tokio::test]
    async fn test_long_session_crosses_rekey_boundary() {
        // 100,001 messages one way crosses REKEY_AFTER_MESSAGES (100,000)
        // mid-stream; bidirectional spot-checks prove both directions stay
        // synchronized through (and past) the rekey.
        let (k1, k2) = test_keys();
        let ((mut ra, mut wa), (mut rb, mut wb)) = duplex_sessions(k1, k2).await;
        let mut buf = [0u8; 16];
        for i in 0..100_001u32 {
            let msg = format!("m{:06}", i);
            wa.send(msg.as_bytes()).await.unwrap();
            rb.read_exact(&mut buf[..7]).await.unwrap();
            assert_eq!(&buf[..7], msg.as_bytes());
            if i % 25_000 == 0 {
                let back = format!("r{:06}", i);
                wb.send(back.as_bytes()).await.unwrap();
                ra.read_exact(&mut buf[..7]).await.unwrap();
                assert_eq!(&buf[..7], back.as_bytes());
            }
        }
        assert_eq!(wa.session().sent_count(), 100_001);
        assert_eq!(rb.session().received_count(), 100_001);
        wa.send(b"after").await.unwrap();
        rb.read_exact(&mut buf[..5]).await.unwrap();
        assert_eq!(&buf[..5], b"after");
        wb.send(b"back").await.unwrap();
        ra.read_exact(&mut buf[..4]).await.unwrap();
        assert_eq!(&buf[..4], b"back");
    }

    #[tokio::test]
    async fn test_long_session_crosses_two_rekey_boundaries() {
        // 210,001 messages one way crosses REKEY_AFTER_MESSAGES (100,000)
        // twice in a single session. Counters, ordering, and both directions
        // must survive every boundary — a long-lived P2P link rekeys
        // repeatedly without dropping, duplicating, or reordering traffic.
        let (k1, k2) = test_keys();
        let ((mut ra, mut wa), (mut rb, mut wb)) = duplex_sessions(k1, k2).await;
        let mut buf = [0u8; 16];
        for i in 0..210_001u32 {
            let msg = format!("m{:06}", i);
            wa.send(msg.as_bytes()).await.unwrap();
            rb.read_exact(&mut buf[..7]).await.unwrap();
            assert_eq!(&buf[..7], msg.as_bytes());
            if i % 50_000 == 0 {
                let back = format!("r{:06}", i);
                wb.send(back.as_bytes()).await.unwrap();
                ra.read_exact(&mut buf[..7]).await.unwrap();
                assert_eq!(&buf[..7], back.as_bytes());
            }
        }
        assert_eq!(wa.session().sent_count(), 210_001);
        assert_eq!(rb.session().received_count(), 210_001);
        wa.send(b"after2").await.unwrap();
        rb.read_exact(&mut buf[..6]).await.unwrap();
        assert_eq!(&buf[..6], b"after2");
        wb.send(b"back2").await.unwrap();
        ra.read_exact(&mut buf[..5]).await.unwrap();
        assert_eq!(&buf[..5], b"back2");
    }

    #[tokio::test]
    async fn test_fragmented_and_coalesced_delivery() {
        // Write ciphertext in 1-byte drips and multi-frame bursts; the
        // poll state machine must reassemble exactly.
        let (k1, k2) = test_keys();
        let (a, b) = tokio::io::duplex(1 << 20);
        let (mut ar, mut aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);
        let deadline = Instant::now() + Duration::from_secs(10);
        let (r1, r2) = tokio::join!(
            do_noise_handshake(&mut ar, &mut aw, HandshakeRole::Initiator, &k1, deadline),
            do_noise_handshake(&mut br, &mut bw, HandshakeRole::Responder, &k2, deadline)
        );
        let (s1, _) = r1.unwrap();
        let (s2, _) = r2.unwrap();
        let mut burst = Vec::new();
        for word in [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()] {
            let ct = s1.encrypt_chunk(word).unwrap();
            burst.extend_from_slice(&(ct.len() as u32).to_le_bytes());
            burst.extend_from_slice(&ct);
        }
        aw.write_all(&burst).await.unwrap();
        let mut reader = NoiseReader::new(br, s2);
        let mut out = [0u8; 11];
        reader.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"onetwothree");
        drop((ar, bw));
    }

    #[tokio::test]
    async fn test_decrypt_fuzz_random_ciphertext_never_panics() {
        // Deterministic xorshift over the session decrypt path: 2000 random
        // blobs (valid lengths, garbage contents) must fail cleanly — never
        // panic and (up to ~2^-128 forgery odds each) never succeed.
        let (k1, k2) = test_keys();
        let (a, b) = tokio::io::duplex(1 << 20);
        let (mut ar, mut aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);
        let deadline = Instant::now() + Duration::from_secs(10);
        let (r1, r2) = tokio::join!(
            do_noise_handshake(&mut ar, &mut aw, HandshakeRole::Initiator, &k1, deadline),
            do_noise_handshake(&mut br, &mut bw, HandshakeRole::Responder, &k2, deadline)
        );
        let _ = r1.unwrap();
        let (s2, _) = r2.unwrap();
        let mut x: u64 = 0x2545F491_4F6CDD1D;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..2000 {
            // Valid transport-frame lengths (17..=65535 so the length gate
            // passes and the AEAD check is what rejects).
            let len = 17 + (next() % (65_535 - 17)) as usize;
            let mut blob = vec![0u8; len];
            for chunk in blob.chunks_mut(8) {
                let v = next().to_le_bytes();
                let n = chunk.len().min(8);
                chunk.copy_from_slice(&v[..n]);
            }
            assert!(
                s2.decrypt_chunk(&blob).is_err(),
                "random ciphertext must not decrypt"
            );
        }
        let _ = (ar, aw, br, bw);
    }

    #[tokio::test]
    async fn test_one_byte_drip_reassembles() {
        // Adversarial delivery: every byte of a frame arrives alone.
        let (k1, k2) = test_keys();
        let (a, b) = tokio::io::duplex(1 << 20);
        let (mut ar, mut aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);
        let deadline = Instant::now() + Duration::from_secs(10);
        let (r1, r2) = tokio::join!(
            do_noise_handshake(&mut ar, &mut aw, HandshakeRole::Initiator, &k1, deadline),
            do_noise_handshake(&mut br, &mut bw, HandshakeRole::Responder, &k2, deadline)
        );
        let (s1, _) = r1.unwrap();
        let (s2, _) = r2.unwrap();
        // Initiator-encrypted bytes travel aw→br; drip them one byte at a
        // time to prove byte-wise reassembly.
        let ct = s1.encrypt_chunk(b"drip-feed").unwrap();
        let mut frame = (ct.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(&ct);
        for byte in frame {
            aw.write_all(&[byte]).await.unwrap();
        }
        drop(aw);
        let mut reader = NoiseReader::new(br, s2);
        let _ = (ar, bw);
        let mut out = [0u8; 9];
        reader.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"drip-feed");
    }

    #[tokio::test]
    async fn test_handshake_bidi_small_messages() {
        let (k1, k2) = test_keys();
        let ((mut ra, mut wa), (mut rb, mut wb)) = duplex_sessions(k1, k2).await;
        wa.send(b"hello initiator").await.unwrap();
        let mut buf = [0u8; 32];
        rb.read_exact(&mut buf[..15]).await.unwrap();
        assert_eq!(&buf[..15], b"hello initiator");
        wb.send(b"hello responder").await.unwrap();
        ra.read_exact(&mut buf[..15]).await.unwrap();
        assert_eq!(&buf[..15], b"hello responder");
        let _ = (ra, rb);
    }

    #[tokio::test]
    async fn test_large_message_chunked_roundtrip() {
        let (k1, k2) = test_keys();
        let ((ra, mut wa), (mut rb, _)) = duplex_sessions(k1, k2).await;
        // 100 KB spans multiple 32 KiB chunks.
        let big: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        wa.send(&big).await.unwrap();
        let mut out = vec![0u8; big.len()];
        rb.read_exact(&mut out).await.unwrap();
        assert_eq!(out, big);
        let _ = ra;
    }

    #[tokio::test]
    async fn test_both_initiator_fails_without_hang() {
        let (a, b) = tokio::io::duplex(1 << 20);
        let (mut ar, mut aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);
        let deadline = Instant::now() + Duration::from_secs(5);
        let (r1, r2) = tokio::join!(
            do_noise_handshake(
                &mut ar,
                &mut aw,
                HandshakeRole::Initiator,
                &[0xAAu8; 32],
                deadline
            ),
            do_noise_handshake(
                &mut br,
                &mut bw,
                HandshakeRole::Initiator,
                &[0xBBu8; 32],
                deadline
            )
        );
        // Both sides speaking first cannot complete a handshake.
        assert!(r1.is_err() || r2.is_err());
    }

    #[tokio::test]
    async fn test_garbage_handshake_rejected_fast() {
        let (a, b) = tokio::io::duplex(1 << 20);
        let (mut ar, mut aw) = tokio::io::split(a);
        let (br, mut bw) = tokio::io::split(b);
        // Attacker side blasts garbage, then goes silent.
        bw.write_all(&[0xFFu8; 64]).await.unwrap();
        drop(bw);
        drop(br);
        let deadline = Instant::now() + Duration::from_secs(5);
        let res = do_noise_handshake(
            &mut ar,
            &mut aw,
            HandshakeRole::Responder,
            &[0xAAu8; 32],
            deadline,
        )
        .await;
        assert!(res.is_err(), "garbage handshake must fail");
    }

    #[tokio::test]
    async fn test_truncated_handshake_rejected() {
        let (a, b) = tokio::io::duplex(1 << 20);
        let (mut ar, mut aw) = tokio::io::split(a);
        let (br, mut bw) = tokio::io::split(b);
        // Valid length prefix, then EOF mid-message.
        bw.write_all(&100u16.to_le_bytes()).await.unwrap();
        bw.write_all(&[0x11u8; 10]).await.unwrap();
        drop(bw);
        drop(br);
        let deadline = Instant::now() + Duration::from_secs(5);
        let res = do_noise_handshake(
            &mut ar,
            &mut aw,
            HandshakeRole::Responder,
            &[0xAAu8; 32],
            deadline,
        )
        .await;
        assert!(res.is_err(), "truncated handshake must fail");
    }

    #[tokio::test]
    async fn test_handshake_timeout_when_peer_silent() {
        let (a, _b) = tokio::io::duplex(1 << 20);
        let (mut ar, mut aw) = tokio::io::split(a);
        // Responder with a silent initiator and a 300 ms deadline.
        let deadline = Instant::now() + Duration::from_millis(300);
        let start = Instant::now();
        let res = do_noise_handshake(
            &mut ar,
            &mut aw,
            HandshakeRole::Responder,
            &[0xAAu8; 32],
            deadline,
        )
        .await;
        assert!(matches!(res, Err(HandshakeError::Timeout)));
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "timeout must bound the wait"
        );
    }

    #[tokio::test]
    async fn test_oversize_len_rejected_without_big_alloc() {
        let (k1, k2) = test_keys();
        let (a, b) = tokio::io::duplex(1 << 20);
        let (mut ar, mut aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);
        let deadline = Instant::now() + Duration::from_secs(10);
        let (r1, r2) = tokio::join!(
            do_noise_handshake(&mut ar, &mut aw, HandshakeRole::Initiator, &k1, deadline),
            do_noise_handshake(&mut br, &mut bw, HandshakeRole::Responder, &k2, deadline)
        );
        let (s1, _) = r1.unwrap();
        let _ = r2.unwrap();
        // Attacker-in-the-middle frame: u32::MAX length, no body follows.
        // Must fail on the length pre-check without allocating gigabytes.
        // Note: responder halves are dropped so EOF follows the 4 length
        // bytes; the rejection must come from the length check itself.
        bw.write_all(&u32::MAX.to_le_bytes()).await.unwrap();
        drop((br, bw));
        let mut reader = NoiseReader::new(ar, s1);
        let _ = aw;
        let mut one = [0u8; 1];
        let start = Instant::now();
        let res = reader.read_exact(&mut one).await;
        assert!(res.is_err(), "absurd length must be rejected");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "rejection must be immediate, not a timeout"
        );
    }

    #[tokio::test]
    async fn test_tampered_ciphertext_detected() {
        let (k1, k2) = test_keys();
        let (a, b) = tokio::io::duplex(1 << 20);
        let (mut ar, mut aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);
        let deadline = Instant::now() + Duration::from_secs(10);
        let (r1, r2) = tokio::join!(
            do_noise_handshake(&mut ar, &mut aw, HandshakeRole::Initiator, &k1, deadline),
            do_noise_handshake(&mut br, &mut bw, HandshakeRole::Responder, &k2, deadline)
        );
        let (s1, _) = r1.unwrap();
        let (s2, _) = r2.unwrap();
        // Encrypt on one side, tamper a byte in transit, frame manually.
        let mut ct = s1.encrypt_chunk(b"secret").unwrap();
        ct[10] ^= 0xFF;
        let frame = {
            let mut f = (ct.len() as u32).to_le_bytes().to_vec();
            f.extend_from_slice(&ct);
            f
        };
        bw.write_all(&frame).await.unwrap();
        drop((br, bw));
        let _ = (ar, aw, s2.clone());
        // Decrypting the tampered frame must fail (fail closed).
        assert!(s2.decrypt_chunk(&ct).is_err());
    }

    #[tokio::test]
    async fn test_replayed_ciphertext_rejected() {
        let (k1, k2) = test_keys();
        let (a, b) = tokio::io::duplex(1 << 20);
        let (mut ar, mut aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);
        let deadline = Instant::now() + Duration::from_secs(10);
        let (r1, r2) = tokio::join!(
            do_noise_handshake(&mut ar, &mut aw, HandshakeRole::Initiator, &k1, deadline),
            do_noise_handshake(&mut br, &mut bw, HandshakeRole::Responder, &k2, deadline)
        );
        let (s1, _) = r1.unwrap();
        let (s2, _) = r2.unwrap();
        // One ciphertext decrypted twice: the replay hits a spent nonce and
        // must fail. (Transport nonces strictly increase per direction.)
        let ct = s1.encrypt_chunk(b"once").unwrap();
        assert_eq!(s2.decrypt_chunk(&ct).unwrap(), b"once");
        assert!(
            s2.decrypt_chunk(&ct).is_err(),
            "replayed ciphertext must be rejected"
        );
        let _ = (ar, aw, br, bw);
    }

    #[tokio::test]
    async fn test_unexpected_eof_mid_stream() {
        let (k1, k2) = test_keys();
        let ((mut ra, _wa), (rb, mut wb)) = duplex_sessions(k1, k2).await;
        // Peer sends a message, consume part of it, then the peer vanishes
        // entirely (both halves dropped — a vanished peer, not a half-close).
        // (Directions: `wb` feeds `ra`; `wa` feeds `rb`.)
        wb.send(b"partial-reader-test").await.unwrap();
        let mut tmp = [0u8; 8];
        ra.read_exact(&mut tmp).await.unwrap();
        assert_eq!(&tmp, b"partial-");
        drop(wb);
        drop(rb);
        // 11 plaintext bytes remain buffered, then clean EOF; asking for 64
        // must fail (unexpected EOF), not hang and not return short data.
        let mut more = [0u8; 64];
        let res = tokio::time::timeout(Duration::from_secs(5), ra.read_exact(&mut more)).await;
        assert!(matches!(res, Ok(Err(_))), "truncated stream must error");
    }
}
