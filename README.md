# Post-Quantum Signcryption-as-a-Service (PQEaaS)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

Post-Quantum Signcryption-as-a-Service (PQEaaS) is a cloud-based service that provides post-quantum cryptographic signcryption capabilities. This service combines the functionalities of digital signatures and encryption in a single logical step, offering security against both classical and quantum computing attacks.

## What is Post-Quantum Signcryption?

**Signcryption** is a cryptographic primitive that simultaneously provides:
- **Confidentiality** (like encryption)
- **Authentication and Non-repudiation** (like digital signatures)

**Post-Quantum** refers to cryptographic algorithms that are secure against attacks by quantum computers, addressing the threat posed by Shor's algorithm and other quantum algorithms that can break current public-key cryptography systems like RSA and ECC.

### Why PQEaaS?

- **Quantum-Resistant Security**: Protection against future quantum computing threats
- **Efficiency**: Signcryption is more efficient than traditional sign-then-encrypt approaches
- **Simplicity**: Easy-to-use API for integrating post-quantum security
- **As-a-Service Model**: No need to manage complex cryptographic infrastructure
- **Future-Proof**: Prepare your applications for the post-quantum era

## Features

- 🔐 **Post-Quantum Cryptographic Algorithms**: Implementation of NIST-approved post-quantum algorithms
- 🔑 **Key Management**: Secure generation, storage, and management of cryptographic keys
- ✍️ **Digital Signatures**: Post-quantum signature schemes for authentication
- 🔒 **Encryption**: Quantum-resistant encryption for data confidentiality
- 🤝 **Signcryption**: Combined signature and encryption in one efficient operation
- 📡 **RESTful API**: Easy integration with existing applications
- 🔍 **Verification Services**: Signature verification and message unsigncryption
- 📊 **Usage Analytics**: Monitor and track cryptographic operations
- 🛡️ **Security Compliance**: Built with security best practices and standards

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Client Applications                      │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ HTTPS/REST API
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                    API Gateway Layer                         │
│  ┌────────────┐  ┌────────────┐  ┌─────────────┐           │
│  │   Auth     │  │  Rate      │  │   Request   │           │
│  │ Service    │  │  Limiting  │  │ Validation  │           │
│  └────────────┘  └────────────┘  └─────────────┘           │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                   Core Services Layer                        │
│  ┌────────────┐  ┌────────────┐  ┌─────────────┐           │
│  │ Signcrypt  │  │   Verify   │  │    Key      │           │
│  │  Service   │  │  Service   │  │ Management  │           │
│  └────────────┘  └────────────┘  └─────────────┘           │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│              Post-Quantum Crypto Library                     │
│  ┌────────────┐  ┌────────────┐  ┌─────────────┐           │
│  │  Dilithium │  │   Kyber    │  │   Falcon    │           │
│  │ (Signature)│  │    (KEM)   │  │ (Signature) │           │
│  └────────────┘  └────────────┘  └─────────────┘           │
└─────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites

- Node.js >= 18.x or Python >= 3.9
- Docker (optional, for containerized deployment)
- API Key (obtain from PQEaaS dashboard)

### Using npm

```bash
npm install pqeaas-client
```

### Using pip

```bash
pip install pqeaas-client
```

### Using Docker

```bash
docker pull pqeaas/client:latest
```

## Quick Start

### JavaScript/Node.js Example

```javascript
const PQEaaS = require('pqeaas-client');

// Initialize client
const client = new PQEaaS({
  apiKey: 'your-api-key',
  endpoint: 'https://api.pqeaas.com'
});

// Generate key pair
const keyPair = await client.generateKeyPair('dilithium3');

// Signcrypt a message
const message = 'Hello, Post-Quantum World!';
const signcrypted = await client.signcrypt({
  message: message,
  senderPrivateKey: keyPair.privateKey,
  recipientPublicKey: recipientPubKey
});

// Unsigncrypt and verify
const result = await client.unsigncrypt({
  ciphertext: signcrypted,
  recipientPrivateKey: recipientPrivKey,
  senderPublicKey: keyPair.publicKey
});

console.log('Decrypted message:', result.message);
console.log('Signature valid:', result.verified);
```

### Python Example

```python
from pqeaas import Client

# Initialize client
client = Client(
    api_key='your-api-key',
    endpoint='https://api.pqeaas.com'
)

# Generate key pair
key_pair = client.generate_key_pair('dilithium3')

# Signcrypt a message
message = 'Hello, Post-Quantum World!'
signcrypted = client.signcrypt(
    message=message,
    sender_private_key=key_pair['private_key'],
    recipient_public_key=recipient_pub_key
)

# Unsigncrypt and verify
result = client.unsigncrypt(
    ciphertext=signcrypted,
    recipient_private_key=recipient_priv_key,
    sender_public_key=key_pair['public_key']
)

print(f"Decrypted message: {result['message']}")
print(f"Signature valid: {result['verified']}")
```

### cURL Example

```bash
# Generate key pair
curl -X POST https://api.pqeaas.com/v1/keys/generate \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"algorithm": "dilithium3"}'

# Signcrypt a message
curl -X POST https://api.pqeaas.com/v1/signcrypt \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "SGVsbG8sIFBvc3QtUXVhbnR1bSBXb3JsZCE=",
    "sender_private_key": "...",
    "recipient_public_key": "..."
  }'
```

## API Reference

### Authentication

All API requests require authentication using an API key:

```
Authorization: Bearer YOUR_API_KEY
```

### Endpoints

#### Generate Key Pair

```
POST /v1/keys/generate
```

**Request Body:**
```json
{
  "algorithm": "dilithium3" // or "dilithium2", "dilithium5", "falcon512", "falcon1024"
}
```

**Response:**
```json
{
  "public_key": "base64_encoded_public_key",
  "private_key": "base64_encoded_private_key",
  "algorithm": "dilithium3",
  "key_id": "unique_key_identifier"
}
```

#### Signcrypt Message

```
POST /v1/signcrypt
```

**Request Body:**
```json
{
  "message": "base64_encoded_message",
  "sender_private_key": "base64_encoded_private_key",
  "recipient_public_key": "base64_encoded_public_key"
}
```

**Response:**
```json
{
  "ciphertext": "base64_encoded_signcrypted_data",
  "algorithm": "dilithium3-kyber1024",
  "timestamp": "2026-01-16T14:53:27Z"
}
```

#### Unsigncrypt Message

```
POST /v1/unsigncrypt
```

**Request Body:**
```json
{
  "ciphertext": "base64_encoded_signcrypted_data",
  "recipient_private_key": "base64_encoded_private_key",
  "sender_public_key": "base64_encoded_public_key"
}
```

**Response:**
```json
{
  "message": "base64_encoded_original_message",
  "verified": true,
  "timestamp": "2026-01-16T14:53:27Z"
}
```

## Supported Algorithms

### Signature Schemes

- **CRYSTALS-Dilithium** (NIST Level 2, 3, 5)
  - Dilithium2: ~128-bit security
  - Dilithium3: ~192-bit security
  - Dilithium5: ~256-bit security

- **Falcon** (NIST Level 1, 5)
  - Falcon-512: ~128-bit security
  - Falcon-1024: ~256-bit security

### Key Encapsulation Mechanisms (KEM)

- **CRYSTALS-Kyber** (NIST Level 1, 3, 5)
  - Kyber512: ~128-bit security
  - Kyber768: ~192-bit security
  - Kyber1024: ~256-bit security

## Security Considerations

### Best Practices

1. **Key Management**
   - Never expose private keys in client-side code
   - Rotate keys regularly
   - Use the key management service for secure storage

2. **API Key Security**
   - Store API keys in environment variables
   - Never commit API keys to version control
   - Rotate API keys periodically

3. **Message Size**
   - Be aware of message size limitations
   - Consider chunking large messages
   - Use appropriate security levels for your use case

4. **Network Security**
   - Always use HTTPS for API communications
   - Implement certificate pinning in production
   - Use rate limiting to prevent abuse

### Threat Model

PQEaaS protects against:
- Classical cryptanalytic attacks
- Quantum computer attacks (Shor's algorithm, Grover's algorithm)
- Man-in-the-middle attacks (with proper certificate validation)
- Message tampering and forgery

### Compliance

- NIST Post-Quantum Cryptography Standards
- FIPS 140-3 compliance (in progress)
- GDPR compliant data handling

## Performance Characteristics

### Operation Timings (Approximate)

| Operation | Dilithium3 | Falcon-512 | Kyber1024 |
|-----------|------------|------------|-----------|
| Key Generation | 50 μs | 200 μs | 30 μs |
| Signing | 150 μs | 500 μs | - |
| Verification | 80 μs | 100 μs | - |
| Encapsulation | - | - | 100 μs |
| Decapsulation | - | - | 120 μs |
| Signcryption | ~250 μs | ~700 μs | - |

### Key and Signature Sizes

| Algorithm | Public Key | Private Key | Signature |
|-----------|------------|-------------|-----------|
| Dilithium2 | 1.3 KB | 2.5 KB | 2.4 KB |
| Dilithium3 | 2.0 KB | 4.0 KB | 3.3 KB |
| Dilithium5 | 2.6 KB | 4.9 KB | 4.6 KB |
| Falcon-512 | 897 B | 1.3 KB | 666 B |
| Falcon-1024 | 1.8 KB | 2.3 KB | 1.3 KB |

## Pricing

Visit our [pricing page](https://pqeaas.com/pricing) for current pricing information.

### Free Tier
- 1,000 operations/month
- Basic support
- Standard algorithms

### Pro Tier
- 100,000 operations/month
- Priority support
- All algorithms
- Analytics dashboard

### Enterprise
- Unlimited operations
- 24/7 dedicated support
- Custom deployment options
- SLA guarantees

## Development

### Building from Source

```bash
# Clone the repository
git clone https://github.com/itspthereee/Post-Quantum-Signcryption-as-a-Service.git
cd Post-Quantum-Signcryption-as-a-Service

# Install dependencies
npm install

# Run tests
npm test

# Build
npm run build
```

### Running Tests

```bash
# Run all tests
npm test

# Run specific test suite
npm test -- --grep "signcryption"

# Run with coverage
npm run test:coverage
```

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Write or update tests
5. Ensure all tests pass
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Code of Conduct

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

## Documentation

- [API Documentation](https://docs.pqeaas.com)
- [Developer Guide](https://docs.pqeaas.com/guides)
- [Security Whitepaper](https://pqeaas.com/whitepaper.pdf)
- [FAQ](https://pqeaas.com/faq)

## Roadmap

- [x] NIST PQC Algorithm Integration
- [x] RESTful API
- [x] Key Management Service
- [ ] GraphQL API
- [ ] WebSocket Support for Real-time Operations
- [ ] Multi-party Signcryption
- [ ] Threshold Cryptography
- [ ] Hardware Security Module (HSM) Integration
- [ ] Blockchain Integration
- [ ] Mobile SDK (iOS/Android)

## Support

- 📧 Email: support@pqeaas.com
- 💬 Discord: [Join our community](https://discord.gg/pqeaas)
- 🐦 Twitter: [@PQEaaS](https://twitter.com/pqeaas)
- 📖 Documentation: [docs.pqeaas.com](https://docs.pqeaas.com)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- NIST Post-Quantum Cryptography Standardization Project
- CRYSTALS Team (Dilithium and Kyber)
- Falcon Development Team
- Open Quantum Safe Project
- All our contributors and supporters

## Citation

If you use PQEaaS in your research, please cite:

```bibtex
@software{pqeaas2026,
  title = {Post-Quantum Signcryption-as-a-Service},
  author = {PQEaaS Team},
  year = {2026},
  url = {https://github.com/itspthereee/Post-Quantum-Signcryption-as-a-Service}
}
```

## Disclaimer

This software is provided for research and development purposes. While we strive for the highest security standards, users should conduct their own security audits before deploying in production environments. Post-quantum cryptography is an evolving field, and standards may change as research progresses.

---

**Made with ❤️ for a quantum-safe future**