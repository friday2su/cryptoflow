/**
 * Supported hash algorithms
 */
export type HashAlgorithm = 'sha256' | 'sha512' | 'sha384' | 'sha224' | 'md5' | 'sha1';
/**
 * Supported digital signature algorithms
 */
export type SignatureAlgorithm = 'RSA-SHA256' | 'RSA-SHA512' | 'RSA-SHA1' | 'ecdsa-with-SHA256' | 'ecdsa-with-SHA512' | 'ecdsa-with-SHA1' | 'ed25519' | 'ed448';
/**
 * Supported elliptic curves
 */
export type EllipticCurve = 'secp256k1' | 'secp384r1' | 'secp521r1' | 'prime256v1' | 'ed25519' | 'ed448';
/**
 * Password generation options
 */
export interface PasswordOptions {
    /** Include numbers (0-9) */
    numbers?: boolean;
    /** Include symbols (!@#$%^&*()_+-=[]{}|;:,.<>?) */
    symbols?: boolean;
    /** Include uppercase letters (A-Z) */
    uppercase?: boolean;
    /** Include lowercase letters (a-z) */
    lowercase?: boolean;
}
/**
 * ECDH key exchange result
 */
export interface ECDHResult {
    /** ECDH private key */
    privateKey: Buffer;
    /** ECDH public key */
    publicKey: Buffer;
    /** Function to compute shared secret with other party's public key */
    computeSecret: (otherPublicKey: Buffer) => Buffer;
}
/**
 * Diffie-Hellman key exchange result
 */
export interface DHResult {
    /** DH private key */
    privateKey: Buffer;
    /** DH public key */
    publicKey: Buffer;
    /** DH prime */
    prime: Buffer;
    /** DH generator */
    generator: Buffer;
    /** Function to compute shared secret with other party's public key */
    computeSecret: (otherPublicKey: Buffer) => Buffer;
}
/**
 * RSA key pair
 */
export interface RSAKeyPair {
    /** RSA public key in PEM format */
    publicKey: string;
    /** RSA private key in PEM format */
    privateKey: string;
}
/**
 * Ed25519 key pair
 */
export interface Ed25519KeyPair {
    /** Ed25519 public key in PEM format */
    publicKey: string;
    /** Ed25519 private key in PEM format */
    privateKey: string;
}
/**
 * Key derivation result
 */
export interface KeyDerivationResult {
    /** Derived key */
    key: Buffer;
    /** Salt used for derivation */
    salt: Buffer;
}
/**
 * Cryptographic commitment result
 */
export interface CommitmentResult {
    /** Commitment hash */
    commitment: string;
    /** Data needed to open/verify the commitment */
    opening: {
        /** Original value that was committed */
        value: string | Buffer;
        /** Random nonce used in commitment */
        nonce: Buffer;
    };
}
/**
 * Multi-hash result type
 */
export type MultiHashResult = Record<string, string>;
/**
 * Scrypt options
 */
export interface ScryptOptions {
    /** CPU/memory cost parameter (must be power of 2) */
    N?: number;
    /** Block size parameter */
    r?: number;
    /** Parallelization parameter */
    p?: number;
    /** Maximum memory (in bytes) */
    maxmem?: number;
}
/**
 * Error types that can be thrown by CryptoFlow
 */
export type CryptoFlowError = 'InvalidKeyLength' | 'InvalidArgument' | 'EncryptionError' | 'DecryptionError' | 'SignatureError' | 'KeyDerivationError' | 'RandomGenerationError';
/**
 * Custom error class for CryptoFlow
 */
export declare class CryptoFlowException extends Error {
    readonly type: CryptoFlowError;
    constructor(type: CryptoFlowError, message: string);
}
