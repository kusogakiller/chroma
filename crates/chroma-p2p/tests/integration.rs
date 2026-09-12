use std::net::SocketAddr;

use chroma_core::hash::Hash;
use chroma_p2p::sync::{ChainSyncer, SyncCommand, SyncState};

fn regtest_genesis_hash() -> Hash {
    chroma_consensus::build_genesis_block_with_bits(chroma_core::types::CompactTarget(0x20ffffff))
        .hash()
}

#[tokio::test]
async fn test_two_node_handshake() {
    let addr1: SocketAddr = "127.0.0.1:19101".parse().unwrap();
    let addr2: SocketAddr = "127.0.0.1:19102".parse().unwrap();

    let genesis_hash = regtest_genesis_hash();

    let dir1 = std::env::temp_dir().join("chroma_integ_1");
    let dir2 = std::env::temp_dir().join("chroma_integ_2");
    let _ = std::fs::remove_dir_all(&dir1);
    let _ = std::fs::remove_dir_all(&dir2);

    let config1 = chroma_p2p::NodeConfig::new(addr1, genesis_hash)
        .with_data_dir(dir1.clone())
        .with_network(chroma_p2p::NetworkConfig::regtest());

    let config2 = chroma_p2p::NodeConfig::new(addr2, genesis_hash)
        .with_data_dir(dir2.clone())
        .with_connect_addrs(vec![addr1])
        .with_network(chroma_p2p::NetworkConfig::regtest());

    let mut node1 = chroma_p2p::Node::new(config1);
    let mut node2 = chroma_p2p::Node::new(config2);

    let mut events1 = node1.event_rx().unwrap();
    let mut events2 = node2.event_rx().unwrap();

    node1.run().await.unwrap();
    node2.run().await.unwrap();

    let connected = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            tokio::select! {
                Some(event) = events1.recv() => {
                    if matches!(event, chroma_p2p::NodeEvent::PeerConnected(_)) {
                        return true;
                    }
                }
                Some(event) = events2.recv() => {
                    if matches!(event, chroma_p2p::NodeEvent::PeerConnected(_)) {
                        return true;
                    }
                }
            }
        }
    })
    .await
    .unwrap_or(false);

    assert!(connected, "nodes should connect within 5 seconds");

    node1.shutdown();
    node2.shutdown();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let _ = std::fs::remove_dir_all(&dir1);
    let _ = std::fs::remove_dir_all(&dir2);
}

#[tokio::test]
async fn test_node_creation_and_shutdown() {
    let addr: SocketAddr = "127.0.0.1:19103".parse().unwrap();
    let genesis_hash = regtest_genesis_hash();

    let dir = std::env::temp_dir().join("chroma_integ_shutdown");
    let _ = std::fs::remove_dir_all(&dir);

    let config = chroma_p2p::NodeConfig::new(addr, genesis_hash)
        .with_data_dir(dir.clone())
        .with_network(chroma_p2p::NetworkConfig::regtest());

    let mut node = chroma_p2p::Node::new(config);
    let _events = node.event_rx().unwrap();

    node.run().await.unwrap();
    node.shutdown();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_sync_state_machine_integration() {
    let genesis = chroma_consensus::build_genesis_block();
    let genesis_hash = genesis.hash();

    let mut syncer = ChainSyncer::new(genesis_hash);
    assert_eq!(syncer.state, SyncState::Idle);

    let peer = "127.0.0.1:8333".parse().unwrap();
    let msg = syncer.start_header_sync(peer, genesis_hash);
    assert_eq!(syncer.state, SyncState::SyncingHeaders);
    assert_eq!(msg.start_hash, genesis_hash);
    assert_eq!(msg.stop_hash, Hash::ZERO);

    let cmds = syncer.received_headers(vec![]);
    assert_eq!(syncer.state, SyncState::CaughtUp);
    assert!(cmds.iter().any(|c| matches!(c, SyncCommand::SyncComplete)));
}

#[test]
fn test_node_config_regtest() {
    let addr: SocketAddr = "127.0.0.1:8333".parse().unwrap();
    let genesis_hash = regtest_genesis_hash();

    let config = chroma_p2p::NodeConfig::new(addr, genesis_hash)
        .with_network(chroma_p2p::NetworkConfig::regtest());

    assert!(config.network.regtest);
    assert_ne!(config.network.magic, chroma_p2p::wire::MAGIC);
}

#[test]
fn test_storage_chain_state_roundtrip() {
    let storage = chroma_storage::Storage::open_temporary().unwrap();
    let genesis = chroma_consensus::build_genesis_block();
    let genesis_hash = genesis.hash();

    storage.apply_block(&genesis).unwrap();
    let work = chroma_core::u256::U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
        &genesis.header.bits.to_full_target(),
    ));
    let tip = chroma_storage::PersistedTip {
        height: 0,
        hash: genesis_hash,
        cumulative_work: work.to_be_bytes(),
        supply: 0,
    };
    storage.put_tip(&tip).unwrap();
    storage.flush().unwrap();

    let loaded_tip = storage.get_tip().unwrap().unwrap();
    assert_eq!(loaded_tip.height, 0);
    assert_eq!(loaded_tip.hash, genesis_hash);
}
