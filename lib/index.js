"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CryptoFlow = void 0;
const node_crypto_1 = require("node:crypto");
const types_1 = require("./types");
class CryptoFlow {
    /**
     * Generates a random key for encryption
     * @param length Length of the key in bytes
     * @returns Random key as Buffer
     */
    static generateKey(length = 32) {
        return (0, node_crypto_1.randomBytes)(length);
    }
    /**
     * Encrypts data using AES-256-GCM
     * @param data Data to encrypt
     * @param key Encryption key
     * @returns Encrypted data with IV and auth tag
     */
    static encrypt(data, key) {
        const iv = (0, node_crypto_1.randomBytes)(this.IV_LENGTH);
        const cipher = (0, node_crypto_1.createCipheriv)(this.DEFAULT_ALGORITHM, key, iv);
        const encrypted = Buffer.concat([
            cipher.update(typeof data === 'string' ? data : data.toString(), this.ENCODING),
            cipher.final()
        ]);
        const tag = cipher.getAuthTag();
        return Buffer.concat([iv, tag, encrypted]).toString('base64');
    }
    /**
     * Decrypts AES-256-GCM encrypted data
     * @param encryptedData Encrypted data (Base64)
     * @param key Decryption key
     * @returns Decrypted data
     */
    static decrypt(encryptedData, key) {
        const data = Buffer.from(encryptedData, 'base64');
        const iv = data.slice(0, this.IV_LENGTH);
        const tag = data.slice(this.IV_LENGTH, this.IV_LENGTH + this.TAG_LENGTH);
        const encrypted = data.slice(this.IV_LENGTH + this.TAG_LENGTH);
        const decipher = (0, node_crypto_1.createDecipheriv)(this.DEFAULT_ALGORITHM, key, iv);
        decipher.setAuthTag(tag);
        return Buffer.concat([
            decipher.update(encrypted),
            decipher.final()
        ]).toString(this.ENCODING);
    }
    /**
     * Generates a secure hash using SHA-256
     * @param data Data to hash
     * @returns Hashed data
     */
    static hash(data) {
        return (0, node_crypto_1.createHash)('sha256')
            .update(typeof data === 'string' ? data : data.toString())
            .digest('hex');
    }
    /**
     * Signs data using HMAC-SHA256
     * @param data Data to sign
     * @param key Signing key
     * @returns Signature
     */
    static sign(data, key) {
        return (0, node_crypto_1.createHmac)('sha256', key)
            .update(typeof data === 'string' ? data : data.toString())
            .digest('hex');
    }
    /**
     * Verifies HMAC signature
     * @param data Original data
     * @param signature Signature to verify
     * @param key Signing key
     * @returns Boolean indicating if signature is valid
     */
    static verify(data, signature, key) {
        const computedSignature = this.sign(data, key);
        return computedSignature === signature;
    }
    /**
     * Generates an RSA key pair
     * @param keySize Size of the key in bits (default: 2048)
     * @returns Object containing public and private keys in PEM format
     */
    static generateRSAKeyPair(keySize = this.RSA_KEY_SIZE) {
        const { publicKey, privateKey } = (0, node_crypto_1.generateKeyPairSync)('rsa', {
            modulusLength: keySize,
            publicExponent: this.RSA_PUBLIC_EXPONENT,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });
        return { publicKey, privateKey };
    }
    /**
     * Encrypts data using RSA
     * @param data Data to encrypt
     * @param publicKey Public key in PEM format
     * @returns Encrypted data in Base64 format
     */
    static rsaEncrypt(data, publicKey) {
        const encrypted = (0, node_crypto_1.publicEncrypt)({
            key: publicKey,
            padding: node_crypto_1.constants.RSA_PKCS1_OAEP_PADDING
        }, Buffer.from(typeof data === 'string' ? data : data.toString()));
        return encrypted.toString('base64');
    }
    /**
     * Decrypts RSA encrypted data
     * @param encryptedData Encrypted data in Base64 format
     * @param privateKey Private key in PEM format
     * @returns Decrypted data
     */
    static rsaDecrypt(encryptedData, privateKey) {
        const decrypted = (0, node_crypto_1.privateDecrypt)({
            key: privateKey,
            padding: node_crypto_1.constants.RSA_PKCS1_OAEP_PADDING
        }, Buffer.from(encryptedData, 'base64'));
        return decrypted.toString(this.ENCODING);
    }
    /**
     * Generates a secure password
     * @param length Password length (default: 16)
     * @param options Password generation options
     * @returns Generated password
     * @throws {CryptoFlowException} If password generation fails
     */
    static generatePassword(length = 16, options = {}) {
        try {
            const defaults = {
                numbers: true,
                symbols: true,
                uppercase: true,
                lowercase: true
            };
            const opts = Object.assign(Object.assign({}, defaults), options);
            let chars = '';
            if (opts.numbers)
                chars += '0123456789';
            if (opts.symbols)
                chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
            if (opts.uppercase)
                chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            if (opts.lowercase)
                chars += 'abcdefghijklmnopqrstuvwxyz';
            if (chars.length === 0) {
                throw new types_1.CryptoFlowException('InvalidArgument', 'At least one character type must be enabled');
            }
            let password = '';
            const bytes = (0, node_crypto_1.randomBytes)(length * 2);
            for (let i = 0; i < length; i++) {
                password += chars[bytes[i] % chars.length];
            }
            return password;
        }
        catch (error) {
            if (error instanceof types_1.CryptoFlowException)
                throw error;
            throw new types_1.CryptoFlowException('RandomGenerationError', 'Failed to generate password');
        }
    }
    /**
     * Computes multiple hashes of data using different algorithms
     * @param data Data to hash
     * @param algorithms Array of hash algorithms (default: ['sha256', 'sha512'])
     * @returns Object containing hashes for each algorithm
     * @throws {CryptoFlowException} If hashing fails
     */
    static multiHash(data, algorithms = ['sha256', 'sha512']) {
        try {
            const result = {};
            for (const algo of algorithms) {
                result[algo] = (0, node_crypto_1.createHash)(algo)
                    .update(typeof data === 'string' ? data : data.toString())
                    .digest('hex');
            }
            return result;
        }
        catch (error) {
            throw new types_1.CryptoFlowException('InvalidArgument', 'Invalid hash algorithm specified');
        }
    }
    /**
     * Encodes data to Base64
     * @param data Data to encode
     * @returns Base64 encoded string
     */
    static toBase64(data) {
        return Buffer.from(typeof data === 'string' ? data : data.toString()).toString('base64');
    }
    /**
     * Decodes Base64 data
     * @param data Base64 encoded data
     * @returns Decoded string
     */
    static fromBase64(data) {
        return Buffer.from(data, 'base64').toString(this.ENCODING);
    }
    /**
     * Generates a random string
     * @param length Length of the random string
     * @returns Random string
     */
    static generateRandomString(length = 32) {
        return (0, node_crypto_1.randomBytes)(length).toString('hex');
    }
    /**
     * Encrypts data with a time-based expiration
     * @param data Data to encrypt
     * @param key Encryption key
     * @param expirationMinutes Number of minutes until the data expires
     * @returns Encrypted data with expiration
     */
    static encryptWithExpiration(data, key, expirationMinutes) {
        const expirationTime = Date.now() + expirationMinutes * 60 * 1000;
        const dataWithExpiration = JSON.stringify({
            data: typeof data === 'string' ? data : data.toString(),
            expiresAt: expirationTime
        });
        return this.encrypt(dataWithExpiration, key);
    }
    /**
     * Decrypts time-based encrypted data
     * @param encryptedData Encrypted data
     * @param key Decryption key
     * @returns Decrypted data if not expired, null if expired
     */
    static decryptWithExpiration(encryptedData, key) {
        const decrypted = this.decrypt(encryptedData, key);
        const { data, expiresAt } = JSON.parse(decrypted);
        if (Date.now() > expiresAt) {
            return null;
        }
        return data;
    }
    /**
     * Derives a key from a password using PBKDF2
     * @param password Password to derive key from
     * @param salt Salt for key derivation (optional)
     * @returns Promise resolving to derived key
     */
    static deriveKey(password, salt) {
        return new Promise((resolve, reject) => {
            const usedSalt = salt || (0, node_crypto_1.randomBytes)(this.SALT_LENGTH);
            const iterations = 100000;
            Promise.resolve().then(() => __importStar(require('node:crypto'))).then(({ pbkdf2 }) => {
                pbkdf2(password, usedSalt, iterations, this.KEY_LENGTH, 'sha512', (err, key) => {
                    if (err)
                        reject(err);
                    else
                        resolve({ key, salt: usedSalt });
                });
            }).catch(reject);
        });
    }
    /**
     * Generates an ECDH key pair and computes shared secret
     * @param curve Elliptic curve name (default: 'secp256k1')
     * @returns ECDH key pair and methods
     * @throws {CryptoFlowException} If curve is not supported
     */
    static createECDHKeyExchange(curve = 'secp256k1') {
        try {
            const ecdh = (0, node_crypto_1.createECDH)(curve);
            const privateKey = ecdh.generateKeys();
            const publicKey = ecdh.getPublicKey();
            return {
                privateKey,
                publicKey,
                computeSecret: (otherPublicKey) => ecdh.computeSecret(otherPublicKey)
            };
        }
        catch (error) {
            throw new types_1.CryptoFlowException('InvalidArgument', `Unsupported curve: ${curve}`);
        }
    }
    /**
     * Creates a Diffie-Hellman key exchange instance
     * @param primeLength Length of the prime number in bits (default: 2048)
     * @returns DH key exchange instance and methods
     * @throws {CryptoFlowException} If prime generation fails
     */
    static createDHKeyExchange(primeLength = 2048) {
        try {
            const dh = (0, node_crypto_1.createDiffieHellman)(primeLength);
            const privateKey = dh.generateKeys();
            const publicKey = dh.getPublicKey();
            const prime = dh.getPrime();
            const generator = dh.getGenerator();
            return {
                privateKey,
                publicKey,
                prime,
                generator,
                computeSecret: (otherPublicKey) => dh.computeSecret(otherPublicKey)
            };
        }
        catch (error) {
            throw new types_1.CryptoFlowException('RandomGenerationError', 'Failed to generate DH parameters');
        }
    }
    /**
     * Signs data using various algorithms (RSA or ECDSA)
     * @param data Data to sign
     * @param privateKey Private key in PEM format
     * @param algorithm Signing algorithm (default: 'RSA-SHA256')
     * @returns Digital signature
     * @throws {CryptoFlowException} If signing fails
     */
    static digitalSign(data, privateKey, algorithm = 'RSA-SHA256') {
        try {
            const sign = (0, node_crypto_1.createSign)(algorithm);
            sign.update(typeof data === 'string' ? data : data.toString());
            return sign.sign(privateKey, 'base64');
        }
        catch (error) {
            throw new types_1.CryptoFlowException('SignatureError', 'Failed to create digital signature');
        }
    }
    /**
     * Verifies a digital signature
     * @param data Original data
     * @param signature Signature to verify
     * @param publicKey Public key in PEM format
     * @param algorithm Signing algorithm (default: 'RSA-SHA256')
     * @returns Boolean indicating if signature is valid
     */
    static verifySignature(data, signature, publicKey, algorithm = 'RSA-SHA256') {
        const verify = (0, node_crypto_1.createVerify)(algorithm);
        verify.update(typeof data === 'string' ? data : data.toString());
        return verify.verify(publicKey, signature, 'base64');
    }
    /**
     * Derives a key using Scrypt (memory-hard KDF)
     * @param password Password to derive key from
     * @param salt Salt for key derivation
     * @param keyLength Length of the derived key
     * @param options Scrypt options
     * @returns Promise resolving to derived key
     * @throws {CryptoFlowException} If key derivation fails
     */
    static deriveKeyScrypt(password_1) {
        return __awaiter(this, arguments, void 0, function* (password, salt = (0, node_crypto_1.randomBytes)(32), keyLength = 32, options = {}) {
            const defaultOptions = {
                N: 16384,
                r: 8,
                p: 1,
                maxmem: 32 * 1024 * 1024
            };
            const opts = Object.assign(Object.assign({}, defaultOptions), options);
            try {
                const key = yield new Promise((resolve, reject) => {
                    (0, node_crypto_1.scrypt)(password, salt, keyLength, opts, (err, derivedKey) => {
                        if (err)
                            reject(err);
                        else
                            resolve(derivedKey);
                    });
                });
                return { key, salt };
            }
            catch (error) {
                throw new types_1.CryptoFlowException('KeyDerivationError', 'Failed to derive key using Scrypt');
            }
        });
    }
    /**
     * Generates an Ed25519 key pair for signing
     * @returns Object containing public and private keys
     */
    static generateEd25519KeyPair() {
        return (0, node_crypto_1.generateKeyPairSync)('ed25519', {
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });
    }
    /**
     * Performs constant-time string comparison
     * @param a First string
     * @param b Second string
     * @returns Boolean indicating if strings are equal
     */
    static constantTimeEqual(a, b) {
        const bufA = Buffer.from(a);
        const bufB = Buffer.from(b);
        if (bufA.length !== bufB.length) {
            return false;
        }
        let result = 0;
        for (let i = 0; i < bufA.length; i++) {
            result |= bufA[i] ^ bufB[i];
        }
        return result === 0;
    }
    /**
     * Generates a cryptographically secure random integer
     * @param min Minimum value (inclusive)
     * @param max Maximum value (inclusive)
     * @returns Random integer between min and max
     */
    static getRandomInt(min, max) {
        const range = max - min + 1;
        const bytesNeeded = Math.ceil(Math.log2(range) / 8);
        const maxValid = Math.floor((Math.pow(256, bytesNeeded)) / range) * range - 1;
        let randomValue;
        do {
            randomValue = (0, node_crypto_1.randomBytes)(bytesNeeded).reduce((acc, byte, i) => acc + (byte << (8 * i)), 0);
        } while (randomValue > maxValid);
        return min + (randomValue % range);
    }
    /**
     * Generates a random UUID v4
     * @returns UUID string
     */
    static generateUUID() {
        const bytes = (0, node_crypto_1.randomBytes)(16);
        bytes[6] = (bytes[6] & 0x0f) | 0x40; // Version 4
        bytes[8] = (bytes[8] & 0x3f) | 0x80; // Variant 1
        return bytes.reduce((acc, byte, i) => {
            if (i === 4 || i === 6 || i === 8 || i === 10) {
                acc += '-';
            }
            return acc + byte.toString(16).padStart(2, '0');
        }, '');
    }
    /**
     * Performs key stretching using multiple iterations of hashing
     * @param data Input data
     * @param iterations Number of iterations
     * @param algorithm Hash algorithm to use
     * @returns Stretched key
     */
    static stretchKey(data, iterations = 10000, algorithm = 'sha512') {
        let result = typeof data === 'string' ? Buffer.from(data) : data;
        for (let i = 0; i < iterations; i++) {
            result = (0, node_crypto_1.createHash)(algorithm).update(result).digest();
        }
        return result;
    }
    /**
     * Creates a cryptographic commitment (hash-based commitment scheme)
     * @param value Value to commit to
     * @param nonce Random nonce (optional)
     * @returns Commitment and opening data
     * @throws {CryptoFlowException} If commitment creation fails
     */
    static createCommitment(value, nonce = (0, node_crypto_1.randomBytes)(32)) {
        try {
            const commitment = (0, node_crypto_1.createHash)('sha256')
                .update(Buffer.concat([
                Buffer.from(typeof value === 'string' ? value : value.toString()),
                nonce
            ]))
                .digest('hex');
            return {
                commitment,
                opening: { value, nonce }
            };
        }
        catch (error) {
            throw new types_1.CryptoFlowException('EncryptionError', 'Failed to create commitment');
        }
    }
    /**
     * Verifies a cryptographic commitment
     * @param commitment Original commitment
     * @param opening Opening data
     * @returns Boolean indicating if commitment is valid
     */
    static verifyCommitment(commitment, opening) {
        const { commitment: newCommitment } = this.createCommitment(opening.value, opening.nonce);
        return this.constantTimeEqual(commitment, newCommitment);
    }
}
exports.CryptoFlow = CryptoFlow;
CryptoFlow.DEFAULT_ALGORITHM = 'aes-256-gcm';
CryptoFlow.ENCODING = 'utf8';
CryptoFlow.IV_LENGTH = 16;
CryptoFlow.SALT_LENGTH = 64;
CryptoFlow.KEY_LENGTH = 32;
CryptoFlow.TAG_LENGTH = 16;
CryptoFlow.RSA_KEY_SIZE = 2048;
CryptoFlow.RSA_PUBLIC_EXPONENT = 65537;
