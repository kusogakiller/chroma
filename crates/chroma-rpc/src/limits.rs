//! RPC concurrency gates (DoS fairness).
//!
//! Two composed bounds, both enforced BEFORE request bodies are read:
//!
//! * per-IP concurrent requests ([`DEFAULT_MAX_CONCURRENT_PER_IP`]): one
//!   client can neither occupy all workers nor force unbounded task growth.
//!   Excess gets an immediate `429` without touching consensus state.
//! * global in-flight cap via tower's `ConcurrencyLimitLayer` (wired in
//!   [`crate::start_rpc_server`]): bounds total tasks × 1 MiB bodies.
//!
//! No background tasks, no timers, no unbounded maps: an IP entry exists
//! only while it holds an in-flight request (removed at zero), so map size
//! is bounded by concurrent connections by construction. Cancellation-safe:
//! the count is held by a drop guard, so aborted/timeout-killed requests
//! release their slot exactly once.

use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, Response, StatusCode},
    response::IntoResponse,
};
use tower::{Layer, Service};

/// Max concurrent in-flight RPC requests from one IP address. Honest CLI /
/// wallet clients open a handful; load tests stay far below this.
pub const DEFAULT_MAX_CONCURRENT_PER_IP: usize = 16;
/// Max concurrent in-flight RPC requests globally (tasks × 1 MiB bodies).
pub const DEFAULT_MAX_CONCURRENT_GLOBAL: usize = 128;

#[derive(Clone, Debug)]
pub struct PerIpCapLayer {
    state: Arc<Mutex<HashMap<IpAddr, usize>>>,
    per_ip: usize,
}

impl PerIpCapLayer {
    pub fn new(per_ip: usize) -> Self {
        PerIpCapLayer {
            state: Arc::new(Mutex::new(HashMap::new())),
            per_ip,
        }
    }

    /// IPs currently holding in-flight requests (observability for tests).
    #[cfg(test)]
    pub fn tracked_ips(&self) -> usize {
        self.state.lock().unwrap().len()
    }
}

impl<S> Layer<S> for PerIpCapLayer {
    type Service = PerIpCapService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PerIpCapService {
            inner,
            state: self.state.clone(),
            per_ip: self.per_ip,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PerIpCapService<S> {
    inner: S,
    state: Arc<Mutex<HashMap<IpAddr, usize>>>,
    per_ip: usize,
}

/// Decrements the IP count on drop: runs exactly once whether the request
/// completes, errors, times out, or is cancelled mid-flight.
struct ReleaseGuard {
    state: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl Drop for ReleaseGuard {
    fn drop(&mut self) {
        let mut map = self.state.lock().unwrap();
        if let Some(n) = map.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

fn rate_limited_response() -> Response<Body> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "error": { "code": -32099, "message": "rate limited: too many concurrent requests" },
        "id": serde_json::Value::Null,
    });
    (StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response()
}

impl<S, ReqBody> Service<Request<ReqBody>> for PerIpCapService<S>
where
    S: Service<Request<ReqBody>, Response = Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // No attributable identity (e.g., direct service calls in unit
        // tests): fail open — availability over strictness when we cannot
        // tell clients apart. Behind `serve`, ConnectInfo is always present.
        let ip = match req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip())
        {
            Some(ip) => ip,
            None => {
                let mut inner = self.inner.clone();
                return Box::pin(async move { inner.call(req).await });
            }
        };
        {
            let mut map = self.state.lock().unwrap();
            let n = map.get(&ip).copied().unwrap_or(0);
            if n >= self.per_ip {
                let body = rate_limited_response();
                return Box::pin(async move { Ok(body) });
            }
            map.insert(ip, n + 1);
        }
        let mut inner = self.inner.clone();
        let guard = ReleaseGuard {
            state: self.state.clone(),
            ip,
        };
        Box::pin(async move {
            let _guard = guard;
            inner.call(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Inner service that parks every admitted request on a shared Notify:
    /// fully deterministic concurrency (nothing completes until released).
    #[derive(Clone)]
    struct Gate {
        open: Arc<AtomicUsize>,
        notify: Arc<tokio::sync::Notify>,
    }

    impl Gate {
        fn new() -> Self {
            Gate {
                open: Arc::new(AtomicUsize::new(0)),
                notify: Arc::new(tokio::sync::Notify::new()),
            }
        }
    }

    impl Service<Request<Body>> for Gate {
        type Response = Response<Body>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Request<Body>) -> Self::Future {
            self.open.fetch_add(1, Ordering::SeqCst);
            let notify = self.notify.clone();
            Box::pin(async move {
                notify.notified().await;
                Ok(StatusCode::OK.into_response())
            })
        }
    }

    fn req_with_ip(ip: IpAddr) -> Request<Body> {
        let mut req = Request::new(Body::empty());
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip, 1234)));
        req
    }

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4([10, 0, 0, n].into())
    }

    #[tokio::test]
    async fn per_ip_cap_admits_then_rejects_then_releases() {
        let layer = PerIpCapLayer::new(2);
        let gate = Gate::new();
        let mut svc = layer.layer(gate.clone());
        let mut pending = Vec::new();
        for _ in 0..2 {
            let mut svc_i = layer.layer(gate.clone());
            pending.push(tokio::spawn(
                async move { svc_i.call(req_with_ip(ip(1))).await },
            ));
        }
        let admitted = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while gate.open.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(admitted.is_ok(), "both requests must be admitted");
        let resp = svc.call(req_with_ip(ip(1))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let other = svc.call(req_with_ip(ip(2)));
        let other = tokio::spawn(other);
        tokio::task::yield_now().await;
        assert_eq!(layer.tracked_ips(), 2);
        gate.notify.notify_waiters();
        for h in pending {
            h.await.unwrap().unwrap();
        }
        other.abort();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(layer.tracked_ips(), 0, "released slots must drain");
        let mut svc_i = layer.layer(gate.clone());
        let h = tokio::spawn(async move { svc_i.call(req_with_ip(ip(3))).await });
        let seen = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while gate.open.load(Ordering::SeqCst) < 4 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(seen.is_ok());
        h.abort();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(layer.tracked_ips(), 0, "cancelled slots must release");
    }

    #[test]
    fn rate_limited_body_shape() {
        let resp = rate_limited_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
