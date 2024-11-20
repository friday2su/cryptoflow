# CryptoFlow

A powerful, zero-dependency cryptographic library for Node.js, providing military-grade encryption and comprehensive cryptographic operations with TypeScript support.

[![npm version](https://badge.fury.io/js/cryptoflow.svg)](https://badge.fury.io/js/cryptoflow)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🌟 Features

- ✨ Zero external dependencies
- 🔒 Military-grade encryption (AES-256-GCM)
- 🔑 RSA public-key cryptography
- 📝 Digital signatures
- 🤝 Secure key exchange (ECDH/DH)
- 🔐 Password generation & key derivation
- #️⃣ Multiple hashing algorithms
- 📦 Full TypeScript support

## 📦 Installation

```bash
npm install cryptoflow
```

## 🚀 Quick Start

```typescript
import { CryptoFlow } from 'cryptoflow';

// Symmetric Encryption
const key = CryptoFlow.generateKey();
const encrypted = CryptoFlow.encrypt("sensitive data", key);
const decrypted = CryptoFlow.decrypt(encrypted, key);

// Generate Strong Password
const password = CryptoFlow.generatePassword(16, {
    numbers: true,
    symbols: true,
    uppercase: true,
    lowercase: true
});
```

## 📚 API Reference

### Symmetric Encryption

```typescript
// Generate encryption key
const key = CryptoFlow.generateKey();

// Encrypt data
const encrypted = CryptoFlow.encrypt("sensitive data", key);

// Decrypt data
const decrypted = CryptoFlow.decrypt(encrypted, key);
```

### RSA Encryption

```typescript
// Generate RSA key pair
const keyPair = CryptoFlow.generateRSAKeyPair();

// Encrypt with public key
const encrypted = CryptoFlow.rsaEncrypt("secret message", keyPair.publicKey);

// Decrypt with private key
const decrypted = CryptoFlow.rsaDecrypt(encrypted, keyPair.privateKey);
```

### Digital Signatures

```typescript
// Sign data
const signature = CryptoFlow.digitalSign(data, privateKey);

// Verify signature
const isValid = CryptoFlow.verifySignature(data, signature, publicKey);
```

### Key Exchange

```typescript
// ECDH Key Exchange
const alice = CryptoFlow.createECDHKeyExchange();
const bob = CryptoFlow.createECDHKeyExchange();

// Compute shared secret
const aliceShared = alice.computeSecret(bob.publicKey);
const bobShared = bob.computeSecret(alice.publicKey);
// aliceShared equals bobShared
```

### Password Management

```typescript
// Generate secure password
const password = CryptoFlow.generatePassword(16, {
    numbers: true,
    symbols: true,
    uppercase: true,
    lowercase: true
});

// Derive key from password
const derivedKey = await CryptoFlow.deriveKey("user-password");
```

### Hashing

```typescript
// Single hash
const hash = CryptoFlow.hash("data");

// Multiple hash algorithms
const multiHash = CryptoFlow.multiHash("data", ["sha256", "sha512"]);
```

## 🔒 Security Features

- Uses cryptographically secure random generation
- Implements constant-time comparison to prevent timing attacks
- Follows cryptographic best practices
- Proper error handling for security-related issues

## 🎯 Use Cases

1. **Secure Data Storage**
   - Encrypt sensitive data before storing in databases
   - Protect configuration files
   - Secure file storage systems

2. **User Authentication**
   - Password hashing
   - Token generation
   - Session management

3. **Secure Communication**
   - End-to-end encryption
   - Secure message exchange
   - API authentication

4. **Digital Signatures**
   - Document signing
   - Transaction verification
   - Software updates

## ⚙️ TypeScript Support

CryptoFlow is written in TypeScript and includes comprehensive type definitions:

```typescript
interface PasswordOptions {
    numbers?: boolean;
    symbols?: boolean;
    uppercase?: boolean;
    lowercase?: boolean;
}

interface RSAKeyPair {
    publicKey: string;
    privateKey: string;
}

interface KeyDerivationResult {
    key: Buffer;
    salt: Buffer;
}
```

## 🛡️ Best Practices

1. **Key Management**
   - Securely store encryption keys
   - Use key derivation for password-based keys
   - Rotate keys periodically

2. **Error Handling**
   ```typescript
   try {
       const encrypted = CryptoFlow.encrypt(data, key);
   } catch (error) {
       if (error instanceof CryptoFlowException) {
           console.error('Encryption failed:', error.message);
       }
   }
   ```

3. **Secure Configuration**
   - Use appropriate key sizes
   - Choose strong algorithms
   - Implement proper key storage

## 📋 Requirements

- Node.js 14.0.0 or higher
- TypeScript 4.0.0 or higher (for TypeScript users)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
