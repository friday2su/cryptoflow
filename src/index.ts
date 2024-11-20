import { createCipheriv, createDecipheriv, randomBytes, createHash, createHmac, generateKeyPairSync, publicEncrypt, privateDecrypt, constants, createDiffieHellman, createECDH, createSign, createVerify, scrypt, generatePrime } from 'node:crypto';
import {
  HashAlgorithm,
  SignatureAlgorithm,
  EllipticCurve,
  PasswordOptions,
  ECDHResult,
  DHResult,
  RSAKeyPair,
  Ed25519KeyPair,
  KeyDerivationResult,
  CommitmentResult,
  MultiHashResult,
  ScryptOptions,
  CryptoFlowException
} from './types';

export class CryptoFlow {
  private static readonly DEFAULT_ALGORITHM = 'aes-256-gcm';
  private static readonly ENCODING = 'utf8';
  private static readonly IV_LENGTH = 16;
  private static readonly SALT_LENGTH = 64;
  private static readonly KEY_LENGTH = 32;
  private static readonly TAG_LENGTH = 16;
  private static readonly RSA_KEY_SIZE = 2048;
  private static readonly RSA_PUBLIC_EXPONENT = 65537;

  /**
   * Generates a random key for encryption
   * @param length Length of the key in bytes
   * @returns Random key as Buffer
   */
  public static generateKey(length: number = 32): Buffer {
    return randomBytes(length);
  }

  /**
   * Encrypts data using AES-256-GCM
   * @param data Data to encrypt
   * @param key Encryption key
   * @returns Encrypted data with IV and auth tag
   */
  public static encrypt(data: string | Buffer, key: Buffer): string {
    const iv = randomBytes(this.IV_LENGTH);
    const cipher = createCipheriv(this.DEFAULT_ALGORITHM, key, iv);
    
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
  public static decrypt(encryptedData: string, key: Buffer): string {
    const data = Buffer.from(encryptedData, 'base64');
    
    const iv = data.slice(0, this.IV_LENGTH);
    const tag = data.slice(this.IV_LENGTH, this.IV_LENGTH + this.TAG_LENGTH);
    const encrypted = data.slice(this.IV_LENGTH + this.TAG_LENGTH);

    const decipher = createDecipheriv(this.DEFAULT_ALGORITHM, key, iv);
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
  public static hash(data: string | Buffer): string {
    return createHash('sha256')
      .update(typeof data === 'string' ? data : data.toString())
      .digest('hex');
  }

  /**
   * Signs data using HMAC-SHA256
   * @param data Data to sign
   * @param key Signing key
   * @returns Signature
   */
  public static sign(data: string | Buffer, key: Buffer): string {
    return createHmac('sha256', key)
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
  public static verify(data: string | Buffer, signature: string, key: Buffer): boolean {
    const computedSignature = this.sign(data, key);
    return computedSignature === signature;
  }

  /**
   * Generates an RSA key pair
   * @param keySize Size of the key in bits (default: 2048)
   * @returns Object containing public and private keys in PEM format
   */
  public static generateRSAKeyPair(keySize: number = this.RSA_KEY_SIZE): RSAKeyPair {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
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
  public static rsaEncrypt(data: string | Buffer, publicKey: string): string {
    const encrypted = publicEncrypt(
      {
        key: publicKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING
      },
      Buffer.from(typeof data === 'string' ? data : data.toString())
    );
    return encrypted.toString('base64');
  }

  /**
   * Decrypts RSA encrypted data
   * @param encryptedData Encrypted data in Base64 format
   * @param privateKey Private key in PEM format
   * @returns Decrypted data
   */
  public static rsaDecrypt(encryptedData: string, privateKey: string): string {
    const decrypted = privateDecrypt(
      {
        key: privateKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING
      },
      Buffer.from(encryptedData, 'base64')
    );
    return decrypted.toString(this.ENCODING);
  }

  /**
   * Generates a secure password
   * @param length Password length (default: 16)
   * @param options Password generation options
   * @returns Generated password
   * @throws {CryptoFlowException} If password generation fails
   */
  public static generatePassword(
    length: number = 16,
    options: PasswordOptions = {}
  ): string {
    try {
      const defaults: Required<PasswordOptions> = {
        numbers: true,
        symbols: true,
        uppercase: true,
        lowercase: true
      };

      const opts = { ...defaults, ...options };
      let chars = '';
      if (opts.numbers) chars += '0123456789';
      if (opts.symbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
      if (opts.uppercase) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      if (opts.lowercase) chars += 'abcdefghijklmnopqrstuvwxyz';

      if (chars.length === 0) {
        throw new CryptoFlowException(
          'InvalidArgument',
          'At least one character type must be enabled'
        );
      }

      let password = '';
      const bytes = randomBytes(length * 2);
      for (let i = 0; i < length; i++) {
        password += chars[bytes[i] % chars.length];
      }
      return password;
    } catch (error) {
      if (error instanceof CryptoFlowException) throw error;
      throw new CryptoFlowException(
        'RandomGenerationError',
        'Failed to generate password'
      );
    }
  }

  /**
   * Computes multiple hashes of data using different algorithms
   * @param data Data to hash
   * @param algorithms Array of hash algorithms (default: ['sha256', 'sha512'])
   * @returns Object containing hashes for each algorithm
   * @throws {CryptoFlowException} If hashing fails
   */
  public static multiHash(
    data: string | Buffer,
    algorithms: HashAlgorithm[] = ['sha256', 'sha512']
  ): MultiHashResult {
    try {
      const result: MultiHashResult = {};
      for (const algo of algorithms) {
        result[algo] = createHash(algo)
          .update(typeof data === 'string' ? data : data.toString())
          .digest('hex');
      }
      return result;
    } catch (error) {
      throw new CryptoFlowException(
        'InvalidArgument',
        'Invalid hash algorithm specified'
      );
    }
  }

  /**
   * Encodes data to Base64
   * @param data Data to encode
   * @returns Base64 encoded string
   */
  public static toBase64(data: string | Buffer): string {
    return Buffer.from(typeof data === 'string' ? data : data.toString()).toString('base64');
  }

  /**
   * Decodes Base64 data
   * @param data Base64 encoded data
   * @returns Decoded string
   */
  public static fromBase64(data: string): string {
    return Buffer.from(data, 'base64').toString(this.ENCODING);
  }

  /**
   * Generates a random string
   * @param length Length of the random string
   * @returns Random string
   */
  public static generateRandomString(length: number = 32): string {
    return randomBytes(length).toString('hex');
  }

  /**
   * Encrypts data with a time-based expiration
   * @param data Data to encrypt
   * @param key Encryption key
   * @param expirationMinutes Number of minutes until the data expires
   * @returns Encrypted data with expiration
   */
  public static encryptWithExpiration(
    data: string | Buffer,
    key: Buffer,
    expirationMinutes: number
  ): string {
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
  public static decryptWithExpiration(
    encryptedData: string,
    key: Buffer
  ): string | null {
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
  public static deriveKey(password: string, salt?: Buffer): Promise<{ key: Buffer; salt: Buffer }> {
    return new Promise((resolve, reject) => {
      const usedSalt = salt || randomBytes(this.SALT_LENGTH);
      const iterations = 100000;
      
      import('node:crypto').then(({ pbkdf2 }) => {
        pbkdf2(password, usedSalt, iterations, this.KEY_LENGTH, 'sha512', (err, key) => {
          if (err) reject(err);
          else resolve({ key, salt: usedSalt });
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
  public static createECDHKeyExchange(curve: EllipticCurve = 'secp256k1'): ECDHResult {
    try {
      const ecdh = createECDH(curve);
      const privateKey = ecdh.generateKeys();
      const publicKey = ecdh.getPublicKey();

      return {
        privateKey,
        publicKey,
        computeSecret: (otherPublicKey: Buffer) => ecdh.computeSecret(otherPublicKey)
      };
    } catch (error) {
      throw new CryptoFlowException(
        'InvalidArgument',
        `Unsupported curve: ${curve}`
      );
    }
  }

  /**
   * Creates a Diffie-Hellman key exchange instance
   * @param primeLength Length of the prime number in bits (default: 2048)
   * @returns DH key exchange instance and methods
   * @throws {CryptoFlowException} If prime generation fails
   */
  public static createDHKeyExchange(primeLength: number = 2048): DHResult {
    try {
      const dh = createDiffieHellman(primeLength);
      const privateKey = dh.generateKeys();
      const publicKey = dh.getPublicKey();
      const prime = dh.getPrime();
      const generator = dh.getGenerator();

      return {
        privateKey,
        publicKey,
        prime,
        generator,
        computeSecret: (otherPublicKey: Buffer) => dh.computeSecret(otherPublicKey)
      };
    } catch (error) {
      throw new CryptoFlowException(
        'RandomGenerationError',
        'Failed to generate DH parameters'
      );
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
  public static digitalSign(
    data: string | Buffer,
    privateKey: string,
    algorithm: SignatureAlgorithm = 'RSA-SHA256'
  ): string {
    try {
      const sign = createSign(algorithm);
      sign.update(typeof data === 'string' ? data : data.toString());
      return sign.sign(privateKey, 'base64');
    } catch (error) {
      throw new CryptoFlowException(
        'SignatureError',
        'Failed to create digital signature'
      );
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
  public static verifySignature(
    data: string | Buffer,
    signature: string,
    publicKey: string,
    algorithm: SignatureAlgorithm = 'RSA-SHA256'
  ): boolean {
    const verify = createVerify(algorithm);
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
  public static async deriveKeyScrypt(
    password: string,
    salt: Buffer = randomBytes(32),
    keyLength: number = 32,
    options: ScryptOptions = {}
  ): Promise<KeyDerivationResult> {
    const defaultOptions: Required<ScryptOptions> = {
      N: 16384,
      r: 8,
      p: 1,
      maxmem: 32 * 1024 * 1024
    };

    const opts = { ...defaultOptions, ...options };

    try {
      const key = await new Promise<Buffer>((resolve, reject) => {
        scrypt(password, salt, keyLength, opts, (err, derivedKey) => {
          if (err) reject(err);
          else resolve(derivedKey);
        });
      });
      return { key, salt };
    } catch (error) {
      throw new CryptoFlowException(
        'KeyDerivationError',
        'Failed to derive key using Scrypt'
      );
    }
  }

  /**
   * Generates an Ed25519 key pair for signing
   * @returns Object containing public and private keys
   */
  public static generateEd25519KeyPair(): Ed25519KeyPair {
    return generateKeyPairSync('ed25519', {
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
  public static constantTimeEqual(a: string | Buffer, b: string | Buffer): boolean {
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
  public static getRandomInt(min: number, max: number): number {
    const range = max - min + 1;
    const bytesNeeded = Math.ceil(Math.log2(range) / 8);
    const maxValid = Math.floor((256 ** bytesNeeded) / range) * range - 1;
    
    let randomValue;
    do {
      randomValue = randomBytes(bytesNeeded).reduce((acc, byte, i) => 
        acc + (byte << (8 * i)), 0);
    } while (randomValue > maxValid);
    
    return min + (randomValue % range);
  }

  /**
   * Generates a random UUID v4
   * @returns UUID string
   */
  public static generateUUID(): string {
    const bytes = randomBytes(16);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;  // Version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80;  // Variant 1

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
  public static stretchKey(
    data: string | Buffer,
    iterations: number = 10000,
    algorithm: HashAlgorithm = 'sha512'
  ): Buffer {
    let result = typeof data === 'string' ? Buffer.from(data) : data;
    
    for (let i = 0; i < iterations; i++) {
      result = createHash(algorithm).update(result).digest();
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
  public static createCommitment(
    value: string | Buffer,
    nonce: Buffer = randomBytes(32)
  ): CommitmentResult {
    try {
      const commitment = createHash('sha256')
        .update(Buffer.concat([
          Buffer.from(typeof value === 'string' ? value : value.toString()),
          nonce
        ]))
        .digest('hex');

      return {
        commitment,
        opening: { value, nonce }
      };
    } catch (error) {
      throw new CryptoFlowException(
        'EncryptionError',
        'Failed to create commitment'
      );
    }
  }

  /**
   * Verifies a cryptographic commitment
   * @param commitment Original commitment
   * @param opening Opening data
   * @returns Boolean indicating if commitment is valid
   */
  public static verifyCommitment(
    commitment: string,
    opening: { value: string | Buffer; nonce: Buffer }
  ): boolean {
    const { commitment: newCommitment } = this.createCommitment(
      opening.value,
      opening.nonce
    );
    return this.constantTimeEqual(commitment, newCommitment);
  }
}
