# Mempool Radar

A Bitcoin mempool monitoring service that listens for new transactions and detects various anomalies in real-time.

## Features

- **Real-time transaction monitoring** via ZMQ subscription
- **Anomaly detection:**
  - High fee transactions (overpaying for block space)
  - Large transactions (unusual size or value)
  - RBF (Replace-By-Fee) chains
  - Double-spend attempts
  - Unusual script patterns
  - Mempool congestion events
- **Telegram notifications** for detected anomalies
- **Rate limiting** to prevent notification spam

## Prerequisites

1. **Bitcoin Core node** with:
   - RPC enabled
   - ZMQ enabled with raw transaction notifications
   - Mempool enabled

2. **Bitcoin Core Configuration** (`bitcoin.conf`):
```
# Enable RPC
server=1

# Option 1: Use username/password (optional)
# rpcuser=your_username
# rpcpassword=your_password

# Option 2: Use cookie auth (default, automatic)
# Bitcoin Core will create a .cookie file automatically

# Enable ZMQ for raw transactions
zmqpubrawtx=tcp://127.0.0.1:28332

# Keep mempool
persistmempool=1
```

## Installation

```bash
cargo build --release
```

## Configuration

Configuration can be provided via command-line arguments or environment variables:

### Authentication Methods

Mempool Radar supports three authentication methods (in order of precedence):

1. **Explicit username/password**: Provide `--rpc-user` and `--rpc-password`
2. **Cookie file**: Automatically detected from Bitcoin Core's data directory
3. **Custom cookie file**: Specify with `--cookie-file /path/to/.cookie`

### Command Line Arguments

```bash
# Using automatic cookie authentication (easiest)
./target/release/mempool-radar

# Using explicit username/password
./target/release/mempool-radar \
  --rpc-user your_username \
  --rpc-password your_password

# Using custom cookie file location
./target/release/mempool-radar \
  --cookie-file /custom/path/.cookie

# Full example with all options
./target/release/mempool-radar \
  --rpc-url http://127.0.0.1:8332 \
  --zmq-endpoint tcp://127.0.0.1:28332 \
  --telegram-token YOUR_BOT_TOKEN \
  --telegram-chat-id YOUR_CHAT_ID \
  --high-fee-threshold 100 \
  --large-tx-size 100000 \
  --large-tx-value 10.0
```

### Environment Variables

```bash
export MEMPOOL_RADAR_RPC_URL=http://127.0.0.1:8332
export MEMPOOL_RADAR_RPC_USER=your_username
export MEMPOOL_RADAR_RPC_PASSWORD=your_password
export MEMPOOL_RADAR_ZMQ_ENDPOINT=tcp://127.0.0.1:28332
export MEMPOOL_RADAR_TELEGRAM_TOKEN=YOUR_BOT_TOKEN
export MEMPOOL_RADAR_TELEGRAM_CHAT_ID=YOUR_CHAT_ID
export MEMPOOL_RADAR_HIGH_FEE_THRESHOLD=100
export MEMPOOL_RADAR_LARGE_TX_SIZE=100000
export MEMPOOL_RADAR_LARGE_TX_VALUE=10.0
export MEMPOOL_RADAR_NETWORK=bitcoin  # bitcoin, testnet, signet, or regtest

./target/release/mempool-radar
```

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `--bind` | 0.0.0.0 | Bind address for the webserver |
| `--port` | 3000 | Port for the webserver |
| `--network` | bitcoin | Network (bitcoin/testnet/signet/regtest) |
| `--rpc-url` | http://127.0.0.1:8332 | Bitcoin Core RPC URL |
| `--rpc-user` | None | RPC username (optional) |
| `--rpc-password` | None | RPC password (optional) |
| `--cookie-file` | Auto-detected | Path to Bitcoin Core cookie file |
| `--zmq-endpoint` | tcp://127.0.0.1:28332 | ZMQ endpoint for raw transactions |
| `--telegram-token` | None | Telegram bot token |
| `--telegram-chat-id` | None | Telegram chat ID |
| `--high-fee-threshold` | 100 | High fee threshold (sat/vB above expected) |
| `--large-tx-size` | 100000 | Large transaction size threshold (bytes) |
| `--large-tx-value` | 10.0 | Large transaction value threshold (BTC) |

## Telegram Bot Setup

1. Create a bot with [@BotFather](https://t.me/botfather) on Telegram
2. Get your bot token
3. Get your chat ID by messaging your bot and visiting:
   ```
   https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates
   ```
4. Configure the bot token and chat ID in the environment or command line

## Running

```bash
# Basic run with auto-detected cookie auth (easiest)
./target/release/mempool-radar

# With Telegram notifications
./target/release/mempool-radar \
  --telegram-token YOUR_BOT_TOKEN \
  --telegram-chat-id YOUR_CHAT_ID

# For testnet (cookie file auto-detected from testnet3 directory)
./target/release/mempool-radar \
  --network testnet \
  --rpc-url http://127.0.0.1:18332 \
  --zmq-endpoint tcp://127.0.0.1:28333

# For custom Bitcoin Core data directory
./target/release/mempool-radar \
  --cookie-file /custom/bitcoin/datadir/.cookie
```

## Anomaly Types

### High Fee Transactions
Detects transactions paying significantly more than the current fee estimate (default: 100 sat/vB above expected).

### Large Transactions
Identifies transactions that are either:
- Larger than 100KB in size
- Transfer more than 10 BTC

### RBF Chains
Tracks Replace-By-Fee transactions that replace previous transactions.

### Double Spend Attempts
Detects when multiple transactions try to spend the same inputs.

### Unusual Scripts
Flags transactions with non-standard script types.

### Mempool Congestion
Monitors overall mempool size and alerts when congestion is detected (checked every 5 minutes).

## Development

```bash
# Run in development mode
cargo run

# Run tests
cargo test

# Check code
cargo check
cargo clippy
```

## License

MIT