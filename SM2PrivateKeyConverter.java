import java.math.BigInteger;

/**
 * 可将 SM2 私钥的十六进制字符串转换为十进制大数（BigInteger）
 */
public class SM2PrivateKeyConverter {
    public static void main(String[] args) {
        // 假设已生成的SM2私钥（十六进制字符串，示例值）
        String privateKeyHex = "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2";

        // 将十六进制私钥转换为十进制大数（BigInteger）
        BigInteger privateKeyDec = new BigInteger(privateKeyHex, 16);

        // 输出结果
        System.out.println("SM2私钥（十六进制）：" + privateKeyHex);
        System.out.println("SM2私钥（十进制大数）：" + privateKeyDec);
    }
}
