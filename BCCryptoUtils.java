import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import java.security.SecureRandom;
import java.math.BigInteger;

/**
 * Bouncy Castle 密码学工具类 - 修正版本
 * 提供更安全的随机数生成和哈希计算
 */
public class BCCryptoUtils {

    /**
     * 使用 Bouncy Castle 的 SHA-256 计算哈希
     */
    public static byte[] sha256(byte[] input) {
        SHA256Digest digest = new SHA256Digest();
        digest.update(input, 0, input.length);
        byte[] output = new byte[32]; // SHA-256 输出 32 字节
        digest.doFinal(output, 0);
        return output;
    }

    /**
     * 使用 Bouncy Castle 的安全随机数生成器 - 修正版本
     * 使用更简单的 DigestRandomGenerator 替代复杂的 SP800SecureRandomBuilder
     */
    public static SecureRandom createSecureRandom(byte[] seed) {
        try {
            // 方法1: 使用 DigestRandomGenerator (推荐)
            DigestRandomGenerator drg = new DigestRandomGenerator(new SHA256Digest());
            if (seed != null && seed.length > 0) {
                drg.addSeedMaterial(seed);
            } else {
                // 添加一些系统熵
                drg.addSeedMaterial(System.currentTimeMillis());
                drg.addSeedMaterial(Runtime.getRuntime().freeMemory());
            }

            // 包装成 SecureRandom
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
            // 备选方案: 使用 Java 内置的 SecureRandom
            System.err.println("Bouncy Castle 随机数生成器初始化失败，使用 Java SecureRandom: " + e.getMessage());
            SecureRandom fallback = new SecureRandom();
            if (seed != null) {
                fallback.setSeed(seed);
            }
            return fallback;
        }
    }

    /**
     * 生成密码学安全的随机 BigInteger - 修正版本
     */
    public static BigInteger generateSecureRandomBigInteger(BigInteger modulus, SecureRandom secureRandom) {
        BigInteger result;
        do {
            // 确保生成的数在 [1, modulus-1] 范围内
            result = new BigInteger(modulus.bitLength(), secureRandom);
        } while (result.compareTo(modulus) >= 0 || result.compareTo(BigInteger.ONE) < 0);
        return result;
    }

    /**
     * 生成随机种子字节数组
     */
    public static byte[] generateRandomSeedBytes(int length, SecureRandom secureRandom) {
        byte[] seed = new byte[length];
        secureRandom.nextBytes(seed);
        return seed;
    }

    /**
     * 计算 SHA-256 哈希并返回十六进制字符串
     */
    public static String sha256Hex(String input) {
        byte[] hash = sha256(input.getBytes());
        return bytesToHex(hash);
    }

    /**
     * 字节数组转十六进制字符串
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