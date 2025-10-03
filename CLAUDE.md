# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Mempool Radar is a Bitcoin mempool monitoring service written in Rust that detects transaction anomalies in real-time.
It subscribes to Bitcoin Core's ZMQ sequence feed to receive transaction and block events, analyzes them for unusual
patterns, and sends notifications via Telegram.

## Key Architecture

### Main Components

1. **ZmqListener** (`src/zmq_listener.rs`): Subscribes to Bitcoin Core's ZMQ `sequence` endpoint, which provides events
   for:
    - Transaction added to mempool ('A')
    - Transaction removed from mempool ('R')
    - Block connected ('C')
    - Block disconnected ('D')

   The listener maintains deduplication sets for processed transactions and blocks, and periodically cleans up old
   entries to prevent unbounded memory growth.

2. **Inspector** (`src/inspector.rs`): Analyzes transactions and detects anomalies:
    - Large transactions (>100KB by default)
    - Unusual transaction versions (non-standard)
    - Unusual scripts (non-standard output types, large OP_RETURNs)
    - Dust outputs (with special handling for ephemeral dust transactions)
    - Excessive ancestor/descendant chains
    - Package size violations
    - Taproot-specific anomalies (annex, OP_SUCCESS, unknown leaf versions, unknown witness versions)
    - P2A script detection (bc1pfeessrawgf)

   **Important**: Mempool-specific checks (ancestors, descendants, package size, chain depth) are skipped for
   transactions that come from blocks, as indicated by the `from_block` parameter.

   In general, the Inspector is supposed to determine if the transaction follows normal bitcoin standardness rules.

3. **Notifier** (`src/notifier.rs`): Sends alerts via Telegram with rate limiting (1 message per second). Falls back to
   logging if Telegram is not configured.

4. **Config** (`src/config.rs`): CLI configuration with support for:
    - Multiple authentication methods: username/password, cookie file (auto-detected), or custom cookie path
    - Network selection (bitcoin/testnet/signet/regtest) with automatic cookie file path resolution
    - Thresholds for various anomaly detections

### Data Flow

1. `main.rs` sets up two async tasks:
    - ZMQ listener task receives events and sends transactions to a channel
    - Processor task receives from channel, analyzes transactions, and sends notifications

2. Bitcoin Core RPC client is used for:
    - Fetching raw transactions (when ZMQ notifies of mempool additions)
    - Fetching blocks (when ZMQ notifies of connected blocks)
    - Fetching mempool entry data (ancestors, descendants, package info)
    - Fetching prevout data for each transaction input (to check dust, scripts, etc.)

3. The system processes both mempool transactions and block transactions, but applies different checks based on the
   source.

## Common Commands

### Build and Run

```bash
# Build release binary
cargo build --release

# Run in development
cargo run

# Run with specific network (testnet example)
cargo run -- --network testnet --rpc-url http://127.0.0.1:18332 --zmq-endpoint tcp://127.0.0.1:28333

# Run with Telegram notifications
cargo run -- --telegram-token YOUR_TOKEN --telegram-chat-id YOUR_CHAT_ID
```

### Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_is_p2a

# Run with logging
RUST_LOG=debug cargo test

# Run unit tests only
cargo test --lib

# Run integration tests
cargo test --test zmq_sequence_tests
```

### Development

```bash
# Check code without building
cargo check

# Run linter
cargo clippy

# Format code
cargo fmt

# Watch for changes and rebuild
cargo watch -x check
```

## Bitcoin Core Requirements

The service requires Bitcoin Core with:

- RPC enabled (`server=1`)
- ZMQ sequence endpoint enabled (e.g., `zmqpubsequence=tcp://127.0.0.1:28332`)

Authentication is handled automatically via cookie files by default, with support for explicit credentials if needed.

## Important Implementation Notes

### Transaction Deduplication

The ZmqListener maintains HashSets to track processed transactions and blocks. This is critical because:

- Transactions can appear in both mempool events and block events
- The same block might be announced multiple times
- Memory is bounded by periodic cleanup (10,000 txs, 50 blocks)

### Prevout Fetching

The Inspector fetches previous outputs for every transaction input to:

- Determine if inputs are spending unusual script types
- Calculate fee rates

### Block Processing

When a block is connected, the system:

1. Fetches the full block from Bitcoin Core RPC
2. Skips the coinbase transaction
3. Processes non-coinbase transactions with `from_block=true` to skip mempool-only checks
4. Tracks which transactions were already seen in the mempool to avoid duplicate analysis

## Code Style

**ALWAYS run `cargo fmt` after making code changes to ensure consistent formatting.**
