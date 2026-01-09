package code;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Bouncy Castle cryptographic utility class
 * Provides cryptographically stronger random number generation and hash computation
 */
public class BCCryptoUtils {

    /**
     * Compute SHA-256 hash using Bouncy Castle
     */
    public static byte[] sha256(byte[] input) {
        SHA256Digest digest = new SHA256Digest();
        digest.update(input, 0, input.length);
        byte[] output = new byte[32]; // SHA-256 produces 32 bytes
        digest.doFinal(output, 0);
        return output;
    }

    /**
     * Create a Bouncy Castle secure random generator – revised version
     * Uses the simpler DigestRandomGenerator instead of the intricate SP800SecureRandomBuilder
     */
    public static SecureRandom createSecureRandom(byte[] seed) {
        try {
            // Method 1: DigestRandomGenerator (recommended)
            DigestRandomGenerator drg = new DigestRandomGenerator(new SHA256Digest());
            if (seed != null && seed.length > 0) {
                drg.addSeedMaterial(seed);
            } else {
                // Add system entropy
                drg.addSeedMaterial(System.currentTimeMillis());
                drg.addSeedMaterial(Runtime.getRuntime().freeMemory());
            }

            // Wrap as SecureRandom
            return new SecureRandom() {
                private final DigestRandomGenerator generator = drg;

                @Override
                public void nextBytes(byte[] bytes) {
                    generator.nextBytes(bytes);
                }

                @Override
                public byte[] generateSeed(int numBytes) {
                    byte[] seed = new byte[numBytes];
                    generator.nextBytes(seed);
                    return seed;
                }
            };

        } catch (Exception e) {
            // Fallback: Java built-in SecureRandom
            System.err.println("Bouncy Castle RNG initialisation failed, falling back to Java SecureRandom: " + e.getMessage());
            SecureRandom fallback = new SecureRandom();
            if (seed != null) {
                fallback.setSeed(seed);
            }
            return fallback;
        }
    }

    /**
     * Generate a cryptographically secure random BigInteger – revised version
     */
    public static BigInteger generateSecureRandomBigInteger(BigInteger modulus, SecureRandom secureRandom) {
        BigInteger result;
        do {
            // Ensure the value lies in [1, modulus-1]
            result = new BigInteger(modulus.bitLength(), secureRandom);
        } while (result.compareTo(modulus) >= 0 || result.compareTo(BigInteger.ONE) < 0);
        return result;
    }

    /**
     * Generate random seed bytes
     */
    public static byte[] generateRandomSeedBytes(int length, SecureRandom secureRandom) {
        byte[] seed = new byte[length];
        secureRandom.nextBytes(seed);
        return seed;
    }

    /**
     * Compute SHA-256 hash and return as hexadecimal string
     */
    public static String sha256Hex(String input) {
        byte[] hash = sha256(input.getBytes());
        return bytesToHex(hash);
    }

    /**
     * Convert byte array to hexadecimal string
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}