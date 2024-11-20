import { HashAlgorithm, SignatureAlgorithm, EllipticCurve, PasswordOptions, ECDHResult, DHResult, RSAKeyPair, Ed25519KeyPair, KeyDerivationResult, CommitmentResult, MultiHashResult, ScryptOptions } from './types';
export declare class CryptoFlow {
    private static readonly DEFAULT_ALGORITHM;
    private static readonly ENCODING;
    private static readonly IV_LENGTH;
    private static readonly SALT_LENGTH;
    private static readonly KEY_LENGTH;
    private static readonly TAG_LENGTH;
    private static readonly RSA_KEY_SIZE;
    private static readonly RSA_PUBLIC_EXPONENT;
    /**
     * Generates a random key for encryption
     * @param length Length of the key in bytes
     * @returns Random key as Buffer
     */
    static generateKey(length?: number): Buffer;
    /**
     * Encrypts data using AES-256-GCM
     * @param data Data to encrypt
     * @param key Encryption key
     * @returns Encrypted data with IV and auth tag
     */
    static encrypt(data: string | Buffer, key: Buffer): string;
    /**
     * Decrypts AES-256-GCM encrypted data
     * @param encryptedData Encrypted data (Base64)
     * @param key Decryption key
     * @returns Decrypted data
     */
    static decrypt(encryptedData: string, key: Buffer): string;
    /**
     * Generates a secure hash using SHA-256
     * @param data Data to hash
     * @returns Hashed data
     */
    static hash(data: string | Buffer): string;
    /**
     * Signs data using HMAC-SHA256
     * @param data Data to sign
     * @param key Signing key
     * @returns Signature
     */
    static sign(data: string | Buffer, key: Buffer): string;
    /**
     * Verifies HMAC signature
     * @param data Original data
     * @param signature Signature to verify
     * @param key Signing key
     * @returns Boolean indicating if signature is valid
     */
    static verify(data: string | Buffer, signature: string, key: Buffer): boolean;
    /**
     * Generates an RSA key pair
     * @param keySize Size of the key in bits (default: 2048)
     * @returns Object containing public and private keys in PEM format
     */
    static generateRSAKeyPair(keySize?: number): RSAKeyPair;
    /**
     * Encrypts data using RSA
     * @param data Data to encrypt
     * @param publicKey Public key in PEM format
     * @returns Encrypted data in Base64 format
     */
    static rsaEncrypt(data: string | Buffer, publicKey: string): string;
    /**
     * Decrypts RSA encrypted data
     * @param encryptedData Encrypted data in Base64 format
     * @param privateKey Private key in PEM format
     * @returns Decrypted data
     */
    static rsaDecrypt(encryptedData: string, privateKey: string): string;
    /**
     * Generates a secure password
     * @param length Password length (default: 16)
     * @param options Password generation options
     * @returns Generated password
     * @throws {CryptoFlowException} If password generation fails
     */
    static generatePassword(length?: number, options?: PasswordOptions): string;
    /**
     * Computes multiple hashes of data using different algorithms
     * @param data Data to hash
     * @param algorithms Array of hash algorithms (default: ['sha256', 'sha512'])
     * @returns Object containing hashes for each algorithm
     * @throws {CryptoFlowException} If hashing fails
     */
    static multiHash(data: string | Buffer, algorithms?: HashAlgorithm[]): MultiHashResult;
    /**
     * Encodes data to Base64
     * @param data Data to encode
     * @returns Base64 encoded string
     */
    static toBase64(data: string | Buffer): string;
    /**
     * Decodes Base64 data
     * @param data Base64 encoded data
     * @returns Decoded string
     */
    static fromBase64(data: string): string;
    /**
     * Generates a random string
     * @param length Length of the random string
     * @returns Random string
     */
    static generateRandomString(length?: number): string;
    /**
     * Encrypts data with a time-based expiration
     * @param data Data to encrypt
     * @param key Encryption key
     * @param expirationMinutes Number of minutes until the data expires
     * @returns Encrypted data with expiration
     */
    static encryptWithExpiration(data: string | Buffer, key: Buffer, expirationMinutes: number): string;
    /**
     * Decrypts time-based encrypted data
     * @param encryptedData Encrypted data
     * @param key Decryption key
     * @returns Decrypted data if not expired, null if expired
     */
    static decryptWithExpiration(encryptedData: string, key: Buffer): string | null;
    /**
     * Derives a key from a password using PBKDF2
     * @param password Password to derive key from
     * @param salt Salt for key derivation (optional)
     * @returns Promise resolving to derived key
     */
    static deriveKey(password: string, salt?: Buffer): Promise<{
        key: Buffer;
        salt: Buffer;
    }>;
    /**
     * Generates an ECDH key pair and computes shared secret
     * @param curve Elliptic curve name (default: 'secp256k1')
     * @returns ECDH key pair and methods
     * @throws {CryptoFlowException} If curve is not supported
     */
    static createECDHKeyExchange(curve?: EllipticCurve): ECDHResult;
    /**
     * Creates a Diffie-Hellman key exchange instance
     * @param primeLength Length of the prime number in bits (default: 2048)
     * @returns DH key exchange instance and methods
     * @throws {CryptoFlowException} If prime generation fails
     */
    static createDHKeyExchange(primeLength?: number): DHResult;
    /**
     * Signs data using various algorithms (RSA or ECDSA)
     * @param data Data to sign
     * @param privateKey Private key in PEM format
     * @param algorithm Signing algorithm (default: 'RSA-SHA256')
     * @returns Digital signature
     * @throws {CryptoFlowException} If signing fails
     */
    static digitalSign(data: string | Buffer, privateKey: string, algorithm?: SignatureAlgorithm): string;
    /**
     * Verifies a digital signature
     * @param data Original data
     * @param signature Signature to verify
     * @param publicKey Public key in PEM format
     * @param algorithm Signing algorithm (default: 'RSA-SHA256')
     * @returns Boolean indicating if signature is valid
     */
    static verifySignature(data: string | Buffer, signature: string, publicKey: string, algorithm?: SignatureAlgorithm): boolean;
    /**
     * Derives a key using Scrypt (memory-hard KDF)
     * @param password Password to derive key from
     * @param salt Salt for key derivation
     * @param keyLength Length of the derived key
     * @param options Scrypt options
     * @returns Promise resolving to derived key
     * @throws {CryptoFlowException} If key derivation fails
     */
    static deriveKeyScrypt(password: string, salt?: Buffer, keyLength?: number, options?: ScryptOptions): Promise<KeyDerivationResult>;
    /**
     * Generates an Ed25519 key pair for signing
     * @returns Object containing public and private keys
     */
    static generateEd25519KeyPair(): Ed25519KeyPair;
    /**
     * Performs constant-time string comparison
     * @param a First string
     * @param b Second string
     * @returns Boolean indicating if strings are equal
     */
    static constantTimeEqual(a: string | Buffer, b: string | Buffer): boolean;
    /**
     * Generates a cryptographically secure random integer
     * @param min Minimum value (inclusive)
     * @param max Maximum value (inclusive)
     * @returns Random integer between min and max
     */
    static getRandomInt(min: number, max: number): number;
    /**
     * Generates a random UUID v4
     * @returns UUID string
     */
    static generateUUID(): string;
    /**
     * Performs key stretching using multiple iterations of hashing
     * @param data Input data
     * @param iterations Number of iterations
     * @param algorithm Hash algorithm to use
     * @returns Stretched key
     */
    static stretchKey(data: string | Buffer, iterations?: number, algorithm?: HashAlgorithm): Buffer;
    /**
     * Creates a cryptographic commitment (hash-based commitment scheme)
     * @param value Value to commit to
     * @param nonce Random nonce (optional)
     * @returns Commitment and opening data
     * @throws {CryptoFlowException} If commitment creation fails
     */
    static createCommitment(value: string | Buffer, nonce?: Buffer): CommitmentResult;
    /**
     * Verifies a cryptographic commitment
     * @param commitment Original commitment
     * @param opening Opening data
     * @returns Boolean indicating if commitment is valid
     */
    static verifyCommitment(commitment: string, opening: {
        value: string | Buffer;
        nonce: Buffer;
    }): boolean;
}
