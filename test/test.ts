import { CryptoFlow } from '../src/index';

describe('CryptoFlow', () => {
    const testData = "Hello, World!";

    test('symmetric encryption', () => {
        const key = CryptoFlow.generateKey();
        const encrypted = CryptoFlow.encrypt(testData, key);
        const decrypted = CryptoFlow.decrypt(encrypted, key);
        expect(decrypted).toBe(testData);
    });

    test('password generation', () => {
        const password = CryptoFlow.generatePassword(16, {
            numbers: true,
            symbols: true,
            uppercase: true,
            lowercase: true
        });
        expect(password.length).toBe(16);
    });

    test('RSA encryption', () => {
        const rsaKeyPair = CryptoFlow.generateRSAKeyPair();
        const rsaEncrypted = CryptoFlow.rsaEncrypt(testData, rsaKeyPair.publicKey);
        const rsaDecrypted = CryptoFlow.rsaDecrypt(rsaEncrypted, rsaKeyPair.privateKey);
        expect(rsaDecrypted).toBe(testData);
    });

    test('digital signatures', () => {
        const rsaKeyPair = CryptoFlow.generateRSAKeyPair();
        const signature = CryptoFlow.digitalSign(testData, rsaKeyPair.privateKey);
        const isValid = CryptoFlow.verifySignature(testData, signature, rsaKeyPair.publicKey);
        expect(isValid).toBe(true);
    });

    test('key derivation', async () => {
        const derivedKey = await CryptoFlow.deriveKey('mypassword');
        expect(derivedKey.key.length).toBeGreaterThan(0);
        expect(derivedKey.salt.length).toBeGreaterThan(0);
    });

    test('hashing', () => {
        const hash = CryptoFlow.hash(testData);
        expect(hash.length).toBeGreaterThan(0);
    });

    test('ECDH key exchange', () => {
        const alice = CryptoFlow.createECDHKeyExchange();
        const bob = CryptoFlow.createECDHKeyExchange();
        const aliceShared = alice.computeSecret(bob.publicKey);
        const bobShared = bob.computeSecret(alice.publicKey);
        expect(aliceShared.equals(bobShared)).toBe(true);
    });

    test('commitment scheme', () => {
        const commitment = CryptoFlow.createCommitment('secret');
        const isCommitmentValid = CryptoFlow.verifyCommitment(
            commitment.commitment,
            commitment.opening
        );
        expect(isCommitmentValid).toBe(true);
    });
});
