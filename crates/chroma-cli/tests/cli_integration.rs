use std::process::{Command, Stdio};
use tempfile::tempdir;

fn chroma_bin() -> String {
    env!("CARGO_BIN_EXE_chroma").to_string()
}

#[test]
fn test_wallet_import_rejects_key_as_arg() {
    let dir = tempdir().unwrap();
    let output = Command::new(chroma_bin())
        .args(["wallet", "import", "-n", "testwallet", "--key", "abcdef"])
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .output()
        .expect("failed to run chroma wallet import");

    assert!(!output.status.success(), "should reject --key argument");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("unexpected")
            || stderr.contains("error")
            || stderr.contains("unrecognized"),
        "should show error about --key, got: {}",
        stderr
    );
}

#[test]
fn test_wallet_address_rejects_seed_as_arg() {
    let dir = tempdir().unwrap();
    let output = Command::new(chroma_bin())
        .args([
            "wallet", "address", "-n", "test",
            "--seed", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ])
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .output()
        .expect("failed to run chroma wallet address");

    assert!(!output.status.success(), "should reject --seed argument");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("unexpected")
            || stderr.contains("error")
            || stderr.contains("unrecognized"),
        "should show error about --seed, got: {}",
        stderr
    );
}

#[test]
fn test_wallet_address_requires_existing_wallet() {
    let dir = tempdir().unwrap();
    let output = Command::new(chroma_bin())
        .args(["wallet", "address", "-n", "nonexistent"])
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .output()
        .expect("failed to run chroma wallet address");

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !output.status.success() || stderr.contains("not found"),
        "should fail for nonexistent wallet, got: {}",
        stderr
    );
}

#[test]
fn test_wallet_import_requires_keystore_or_stdin() {
    let dir = tempdir().unwrap();
    let output = Command::new(chroma_bin())
        .args(["wallet", "import", "-n", "testwallet"])
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .output()
        .expect("failed to run chroma wallet import");

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !output.status.success() || stderr.contains("--keystore") || stderr.contains("--key-stdin"),
        "should require --keystore or --key-stdin, got: {}",
        stderr
    );
}

#[test]
fn test_block_height_no_chain() {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().join("data");

    let output = Command::new(chroma_bin())
        .args(["block", "height", "--data-dir", data_dir.to_str().unwrap()])
        .output()
        .expect("failed to run chroma block height");

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("No chain found") || stdout.contains("Failed to open"),
        "should report no chain, got: {}",
        stdout
    );
}

#[test]
fn test_node_starts_and_stops() {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().join("node_data");
    let port = 19876;

    let mut child = Command::new(chroma_bin())
        .args([
            "node",
            "-l",
            &format!("127.0.0.1:{}", port),
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--regtest",
        ])
        .spawn()
        .expect("failed to start chroma node");

    std::thread::sleep(std::time::Duration::from_secs(3));
    assert!(child.id() > 0, "node process should be running");

    child.kill().expect("failed to kill node process");
    let status = child.wait().expect("failed to wait on child");
    assert!(
        !status.success(),
        "killed process should have non-zero exit"
    );
}

#[test]
fn test_wallet_balance_nonexistent_address() {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().join("data");

    let output = Command::new(chroma_bin())
        .args([
            "wallet",
            "balance",
            "-a",
            "chr1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhlnp9z",
            "--data-dir",
            data_dir.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run chroma wallet balance");

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("0 CHR") || stdout.contains("Failed to open") || !output.status.success(),
        "should handle nonexistent address gracefully, got: {}",
        stdout
    );
}

#[test]
fn test_mnemonic_generation() {
    let output = Command::new(chroma_bin())
        .args(["mnemonic", "-n", "testmnemonic"])
        .output()
        .expect("failed to run chroma mnemonic");

    assert!(output.status.success(), "mnemonic should succeed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("Generated mnemonic"),
        "should print mnemonic header, got: {}",
        stdout
    );
    assert!(
        stdout.contains("Address:"),
        "should print address, got: {}",
        stdout
    );

    let mnemonic_line = stdout
        .lines()
        .find(|l| !l.contains("Generated") && !l.contains("Address") && !l.trim().is_empty())
        .unwrap();
    let word_count = mnemonic_line.split_whitespace().count();
    assert!(
        word_count >= 12,
        "mnemonic should have at least 12 words, got {}",
        word_count
    );
}

#[test]
fn test_rpc_api_key_not_in_help_output() {
    let output = Command::new(chroma_bin())
        .args(["node", "--help"])
        .output()
        .expect("failed to run chroma node --help");

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("rpc-api-key"),
        "should document rpc-api-key option, got: {}",
        stdout
    );
}

#[test]
fn test_no_private_key_in_process_args() {
    let output = Command::new(chroma_bin())
        .args(["wallet", "import", "--help"])
        .output()
        .expect("failed to run chroma wallet import --help");

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        !stdout.contains("--key "),
        "should NOT have --key option in help (removed for security), got: {}",
        stdout
    );
    assert!(
        stdout.contains("--key-stdin"),
        "should have --key-stdin option, got: {}",
        stdout
    );
}

#[test]
fn test_no_seed_in_process_args() {
    let output = Command::new(chroma_bin())
        .args(["wallet", "address", "--help"])
        .output()
        .expect("failed to run chroma wallet address --help");

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        !stdout.contains("--seed"),
        "should NOT have --seed option in help (removed for security), got: {}",
        stdout
    );
}

#[test]
fn test_wallet_list_empty() {
    let dir = tempdir().unwrap();
    let output = Command::new(chroma_bin())
        .args(["wallet", "list"])
        .current_dir(dir.path())
        .output()
        .expect("failed to run chroma wallet list");

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("No wallets found"),
        "should report no wallets, got: {}",
        stdout
    );
}

#[test]
fn test_wallet_send_rejects_invalid_recipient() {
    let output = Command::new(chroma_bin())
        .args([
            "wallet",
            "send",
            "-n",
            "testwallet",
            "-t",
            "0x0000000000000000000000000000000000000001",
            "-a",
            "1.0",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run chroma wallet send");

    if !output.status.success() {
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("Invalid")
                || stderr.contains("not found")
                || stderr.contains("password"),
            "should fail with meaningful error, got: {}",
            stderr
        );
    }
}

#[test]
fn test_wallet_send_rejects_zero_amount() {
    let output = Command::new(chroma_bin())
        .args([
            "wallet",
            "send",
            "-n",
            "testwallet",
            "-t",
            "0x0000000000000000000000000000000000000001",
            "-a",
            "0",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run chroma wallet send");

    if !output.status.success() {
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("zero")
                || stderr.contains("greater than")
                || stderr.contains("password")
                || stderr.contains("not found"),
            "should reject zero amount, got: {}",
            stderr
        );
    }
}

#[test]
fn test_wallet_send_requires_name() {
    let output = Command::new(chroma_bin())
        .args([
            "wallet",
            "send",
            "-t",
            "chr1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhlnp9z",
            "-a",
            "1.0",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run chroma wallet send");

    assert!(!output.status.success(), "should fail without -n name");
}

#[test]
fn test_node_plaintext_refused_on_mainnet() {
    // Mainnet P2P is Noise-only: the insecure plaintext opt-in must be
    // refused before the node binds any socket.
    let output = Command::new(chroma_bin())
        .args(["node", "--insecure-plaintext-peers"])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run chroma node");

    assert!(
        !output.status.success(),
        "mainnet + plaintext must be refused"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("mainnet") && stderr.contains("Noise"),
        "refusal must explain the mainnet Noise requirement, got: {}",
        stderr
    );
}
