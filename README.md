# Solana Fellowship Server

A Rust HTTP server for Solana development tasks including keypair generation, SPL token operations, message signing/verification, and transaction instruction creation.

## Features

- 🔑 **Keypair Generation**: Generate new Solana keypairs
- 🪙 **SPL Token Operations**: Create and mint SPL tokens
- ✍️ **Message Signing**: Sign messages with private keys
- ✅ **Signature Verification**: Verify message signatures
- 💰 **SOL Transfers**: Create SOL transfer instructions
- 🎯 **Token Transfers**: Create SPL token transfer instructions

## Quick Start

### Prerequisites

- Rust 1.70+ and Cargo
- Python 3.8+ (for testing)

### Installation

1. Clone the repository:
```bash
git clone <your-repo-url>
cd solana-fellowship-server
```

2. Build and run the server:
```bash
cargo run
```

The server will start on `http://localhost:3000`

### Testing

Install Python dependencies:
```bash
pip install -r requirements.txt
```

Run the test suite:
```bash
python test_endpoints.py
```

## API Endpoints

### Health Check
```http
GET /health
```

### Generate Keypair
```http
POST /keypair
```

### Create SPL Token
```http
POST /token/create
Content-Type: application/json

{
  "payer_private_key": "base58_encoded_private_key",
  "mint_authority_private_key": "base58_encoded_private_key",
  "decimals": 9,
  "freeze_authority": null
}
```

### Mint Tokens
```http
POST /token/mint
Content-Type: application/json

{
  "mint_private_key": "base58_encoded_private_key",
  "mint_authority_private_key": "base58_encoded_private_key",
  "recipient_address": "recipient_public_key",
  "amount": 1000000000
}
```

### Sign Message
```http
POST /message/sign
Content-Type: application/json

{
  "private_key": "base58_encoded_private_key",
  "message": "Hello Solana!"
}
```

### Verify Message
```http
POST /message/verify
Content-Type: application/json

{
  "public_key": "public_key",
  "message": "Hello Solana!",
  "signature": "base64_encoded_signature"
}
```

### Create SOL Transfer Instruction
```http
POST /send/sol
Content-Type: application/json

{
  "sender_private_key": "base58_encoded_private_key",
  "recipient_address": "recipient_public_key",
  "amount_lamports": 1000000
}
```

### Create Token Transfer Instruction
```http
POST /send/token
Content-Type: application/json

{
  "sender_private_key": "base58_encoded_private_key",
  "mint_address": "token_mint_address",
  "recipient_address": "recipient_public_key",
  "amount": 500000000
}
```

## Development

### Project Structure
```
solana-fellowship-server/
├── src/
│   └── main.rs          # Main server implementation
├── Cargo.toml           # Rust dependencies
├── requirements.txt     # Python test dependencies
├── test_endpoints.py    # Comprehensive test suite
└── README.md           # This file
```

### Building
```bash
cargo build --release
```

### Running Tests
```bash
# Run Rust tests
cargo test

# Run Python integration tests
python test_endpoints.py
```

## Deployment

### Render Deployment

1. **Create a Render account** at [render.com](https://render.com)

2. **Connect your GitHub repository** to Render

3. **Create a new Web Service**:
   - Choose your repository
   - Set build command: `cargo build --release`
   - Set start command: `./target/release/solana-fellowship-server`
   - Set environment: `Rust`

4. **Configure environment variables** (if needed):
   - `PORT`: Set to `10000` (Render's default)
   - `RUST_LOG`: Set to `info`

5. **Deploy** and get your live URL!

### Environment Variables

- `PORT`: Server port (default: 3000)
- `RUST_LOG`: Logging level (default: info)

## Error Handling

The server uses custom error types and returns consistent JSON responses:

```json
{
  "success": true,
  "data": { ... },
  "message": "Operation completed successfully"
}
```

Error responses:
```json
{
  "success": false,
  "error": "Error description",
  "message": "What went wrong"
}
```

## Security Notes

- This server is designed for development and testing
- Private keys are processed in memory but not stored
- Use HTTPS in production environments
- Implement proper authentication for production use

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details 