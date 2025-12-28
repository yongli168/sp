import javax.swing.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;

/**
 * 动态阈值秘密共享系统版本7应用程序 - 严格遵循文档方案
 * 实现4.1-4.6节的所有协议和验证
 */
public class DynamicThresholdSecretSharingVersion7App {
    // ============================ 实验参数配置 ============================
    private static final int NUM_PARTICIPANTS = 40;
    private static final int[] THRESHOLDS = {5,7,9,11,13};
    private static final int NUM_EXPERIMENTS = 1000;
    private static final int PRIME_BIT_LENGTH = 256;
    private static final int INCREASE_THRESHOLDS = 4; //扩展阶数
    private static final BigInteger FIXED_256BIT_PRIME = new BigInteger(
            "115792089237316195423570985008687907853269984665640564039457584007908834671663");
    private static final int THREAD_POOL_SIZE = THRESHOLDS.length;

    // ============================ 系统状态变量 ============================
    private BigInteger p;
    private int n;
    private int currentThreshold;
    private int currentMainThreshold;
    public BigInteger secret;
    private List<BigInteger> participantIDs;
    private BigInteger previousSeed;

    // ============================ 系统核心组件 ============================
    private BivariatePolynomial mainPolynomial;
    private List<UnivariatePolynomial> mainShares;
    private List<BigInteger> workingShares;
    private PerformanceStats stats;
    private boolean verbose;

    /**
     * 构造函数：初始化动态阈值秘密共享系统
     */
    public DynamicThresholdSecretSharingVersion7App(int n, int initialThreshold, boolean verbose) {
        this.n = n;
        this.currentThreshold = initialThreshold;
        this.currentMainThreshold = initialThreshold;
        this.p = FIXED_256BIT_PRIME;
        this.participantIDs = generateParticipantIDs(n);
        this.stats = new PerformanceStats();
        this.verbose = verbose;
        this.secret = new BigInteger("73138218979700741375608676119062004991785096625092157987592068860966427730354").mod(p);
        this.previousSeed = new BigInteger("10101010");

        if (verbose) {
            System.out.println("✓ 系统初始化完成 - 参与者数量: " + n + ", 初始阈值: " + initialThreshold);
        }
    }

    /**
     * 生成参与者ID列表
     */
    private List<BigInteger> generateParticipantIDs(int n) {
        List<BigInteger> ids = new ArrayList<>();
        for (int i = 1; i <= n; i++) {
            ids.add(BigInteger.valueOf(i));
        }
        return ids;
    }

    /**
     * 系统初始化：严格按照文档4.2节实现
     */
    public void systemInitialization(BigInteger secret) {
        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("4.2 系统初始化开始");
            System.out.println("=".repeat(60));
        }

        this.secret = secret;

        // 生成对称双变量多项式 - 严格遵循文档4.2节公式
        if (verbose) System.out.println("步骤1: 生成对称双变量多项式 f(x,y)");
        this.mainPolynomial = new BivariatePolynomial(currentThreshold, p, secret, verbose);

        // 生成主份额 - 严格遵循文档4.3.1节
        if (verbose) System.out.println("步骤2: 生成主份额 S_i(y) = f(ID_i, y)");
        this.mainShares = new ArrayList<>();
        for (int i = 0; i < participantIDs.size(); i++) {
            BigInteger id = participantIDs.get(i);
            UnivariatePolynomial share = mainPolynomial.evaluateAtX(id);
            mainShares.add(share);
        }

        // 生成工作份额 - 严格遵循文档4.3.2节
        if (verbose) System.out.println("步骤3: 生成工作份额 T_i = S_i(0) = f(ID_i, 0)");
        this.workingShares = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            BigInteger workingShare = mainShares.get(i).evaluate(BigInteger.ZERO);
            workingShares.add(workingShare);
        }

        long endTime = System.nanoTime();
        stats.addInitTime(endTime - startTime);

        if (verbose) {
            System.out.println("✓ 系统初始化完成");
            System.out.printf("初始化总时间: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }
    }

    /**
     * 安全阈值下调协议：严格按照文档4.4.2节实现
     */
    public void thresholdDecrease(int newThreshold) {
        if (newThreshold >= currentThreshold) {
            throw new IllegalArgumentException("新阈值必须小于当前阈值");
        }

        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("4.4.2 安全阈值下调协议开始");
            System.out.println("=".repeat(60));
            System.out.println("当前阈值: " + currentThreshold + " → 新阈值: " + newThreshold);
        }

        // 步骤1: 本地计算拉格朗日分量 - 严格遵循文档步骤一
        if (verbose) System.out.println("步骤1: 本地计算拉格朗日分量 c_i = S_i(0) × L_i");
        List<BigInteger> lagrangeComponents = computeLagrangeComponents(currentThreshold);

        // 步骤2: 本地生成重共享多项式 - 严格遵循文档步骤二
        if (verbose) System.out.println("步骤2: 本地生成重共享多项式 h_i(x,y)");
        List<BivariatePolynomial> resharePolynomials = generateResharePolynomials(lagrangeComponents, newThreshold);

        // 步骤3: 本地生成加密共享值并广播 - 严格遵循文档步骤三
        if (verbose) System.out.println("步骤3: 生成加密共享值并广播 C_ik = v_ik + k_ik");
        List<List<BigInteger>> encryptedShares = generateEncryptedShares(resharePolynomials);

        // 步骤4: 并行解密与计算工作份额 - 严格遵循文档步骤四
        if (verbose) System.out.println("步骤4: 并行解密并计算新工作份额");
        updateWorkingShares(encryptedShares);

        this.currentThreshold = newThreshold;

        long endTime = System.nanoTime();
        stats.addThresholdAdjustTime(endTime - startTime);

        if (verbose) {
            System.out.println("✓ 安全阈值下调完成");
            System.out.printf("阈值下调总时间: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }
    }

    /**
     * 计算拉格朗日分量 - 辅助方法
     */
    private List<BigInteger> computeLagrangeComponents(int threshold) {
        List<BigInteger> components = new ArrayList<>();
        for (int i = 0; i < threshold; i++) {
            BigInteger lagrangeCoeff = computeLagrangeCoefficient(i, threshold);
            BigInteger mainShareValue = mainShares.get(i).evaluate(BigInteger.ZERO);
            BigInteger component = mainShareValue.multiply(lagrangeCoeff).mod(p);
            components.add(component);
            if (verbose && i < 3) {
                System.out.println("  参与者 P" + (i+1) + " 拉格朗日分量: " + component);
            }
        }
        return components;
    }

    /**
     * 生成重共享多项式 - 辅助方法
     */
    private List<BivariatePolynomial> generateResharePolynomials(List<BigInteger> components, int newThreshold) {
        List<BivariatePolynomial> polynomials = new ArrayList<>();
        for (int i = 0; i < components.size(); i++) {
            BigInteger component = components.get(i);
            BivariatePolynomial poly = new BivariatePolynomial(newThreshold, p, component, false);
            polynomials.add(poly);
        }
        return polynomials;
    }

    /**
     * 生成加密共享值 - 辅助方法
     */
    private List<List<BigInteger>> generateEncryptedShares(List<BivariatePolynomial> resharePolynomials) {
        List<List<BigInteger>> encryptedShares = new ArrayList<>();
        for (int i = 0; i < resharePolynomials.size(); i++) {
            List<BigInteger> encryptedRow = new ArrayList<>();
            BivariatePolynomial poly = resharePolynomials.get(i);

            for (int j = 0; j < n; j++) {
                BigInteger shareValue = poly.evaluate(participantIDs.get(j), BigInteger.ZERO);
                // 使用当前主多项式计算配对密钥 - 严格遵循文档
                BigInteger pairingKey = mainPolynomial.evaluate(participantIDs.get(i), participantIDs.get(j));
                BigInteger encrypted = shareValue.add(pairingKey).mod(p);
                encryptedRow.add(encrypted);
            }
            encryptedShares.add(encryptedRow);
        }
        return encryptedShares;
    }

    /**
     * 更新工作份额 - 辅助方法
     */
    private void updateWorkingShares(List<List<BigInteger>> encryptedShares) {
        List<BigInteger> newWorkingShares = new ArrayList<>();
        for (int k = 0; k < n; k++) {
            BigInteger sum = BigInteger.ZERO;
            for (int i = 0; i < encryptedShares.size(); i++) {
                BigInteger encrypted = encryptedShares.get(i).get(k);
                // 使用当前主多项式计算配对密钥 - 严格遵循文档
                BigInteger pairingKey = mainPolynomial.evaluate(participantIDs.get(k), participantIDs.get(i));
                BigInteger decrypted = encrypted.subtract(pairingKey).mod(p);
                sum = sum.add(decrypted).mod(p);
            }
            newWorkingShares.add(sum);
        }
        this.workingShares = newWorkingShares;
    }

    /**
     * 安全阈值上调协议：严格按照文档4.4.1节实现
     * 优化：采用纯多项式扩展而非叠加方式
     */
    public void thresholdIncrease(int newThreshold) {
        if (newThreshold <= currentThreshold) {
            throw new IllegalArgumentException("新阈值必须大于当前阈值");
        }

        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("4.4.1 安全阈值上调协议开始（优化版）");
            System.out.println("=".repeat(60));
            System.out.println("当前阈值: " + currentThreshold + " → 新阈值: " + newThreshold);
            System.out.println("扩展阶数 k = " + (newThreshold - currentThreshold));
        }

        int k = newThreshold - currentThreshold;

        // 优化步骤1: 直接构造扩展后的多项式 - 严格遵循文档扩展设计
        if (verbose) System.out.println("步骤1: 直接构造扩展后的对称双变量多项式");
        this.mainPolynomial = buildExtendedPolynomialDirectly(newThreshold);

        // 新增: 严格验证扩展多项式
        if (verbose) System.out.println("步骤1.1: 验证扩展多项式符合文档技术要求");
        validateExtendedPolynomial(this.mainPolynomial, currentThreshold, newThreshold);

        // 优化步骤2: 重新生成主份额 - 基于新多项式
        if (verbose) System.out.println("步骤2: 基于扩展多项式重新生成主份额");
        updateMainSharesForExtension(newThreshold);

        // 优化步骤3: 重新生成工作份额
        if (verbose) System.out.println("步骤3: 基于扩展多项式重新生成工作份额");
        updateWorkingSharesForExtension(newThreshold);

        this.currentThreshold = newThreshold;
        this.currentMainThreshold = newThreshold;

        long endTime = System.nanoTime();
        stats.addThresholdIncreaseTime(endTime - startTime);

        if (verbose) {
            System.out.println("✓ 安全阈值上调完成（严格遵循文档扩展方案）");
            System.out.printf("阈值上调总时间: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }
    }

    /**
     * 验证扩展多项式是否符合文档技术要求
     */
    private void validateExtendedPolynomial(BivariatePolynomial extendedPoly, int originalThreshold, int newThreshold) {
        // 验证1: 低阶系数保持不变
        for (int i = 0; i < originalThreshold; i++) {
            for (int j = 0; j < originalThreshold; j++) {
                if (!extendedPoly.coefficients[i][j].equals(mainPolynomial.coefficients[i][j])) {
                    throw new IllegalStateException("低阶系数在扩展过程中被修改");
                }
            }
        }

        // 验证2: 对称性保持
        for (int i = 0; i < newThreshold; i++) {
            for (int j = i; j < newThreshold; j++) {
                if (!extendedPoly.coefficients[i][j].equals(extendedPoly.coefficients[j][i])) {
                    throw new IllegalStateException("扩展多项式对称性被破坏");
                }
            }
        }

        // 验证3: 秘密值保持
        BigInteger extendedSecret = extendedPoly.evaluate(BigInteger.ZERO, BigInteger.ZERO);
        if (!extendedSecret.equals(secret)) {
            throw new IllegalStateException("扩展后秘密值不匹配: " + extendedSecret + " != " + secret);
        }

        // 验证4: 阶数正确性
        if (extendedPoly.coefficients.length != newThreshold) {
            throw new IllegalStateException("扩展多项式阶数不正确");
        }

        if (verbose) {
            System.out.println("  ✓ 扩展多项式验证通过:");
            System.out.println("    - 低阶系数保持完整");
            System.out.println("    - 对称性约束满足");
            System.out.println("    - 秘密值保持正确");
            System.out.println("    - 多项式阶数: " + (newThreshold - 1));
        }
    }

    /**
     * 基于扩展多项式重新生成工作份额 - 严格遵循文档工作份额定义
     */
    private void updateWorkingSharesForExtension(int newThreshold) {
        if (verbose) System.out.println("  重新计算 " + n + " 个参与者的工作份额");

        for (int i = 0; i < n; i++) {
            // 直接基于扩展后的多项式计算新工作份额
            BigInteger newWorkingShare = mainPolynomial.evaluate(participantIDs.get(i), BigInteger.ZERO);
            workingShares.set(i, newWorkingShare);

            if (verbose && i < 2) {
                System.out.println("    参与者 P" + (i+1) + " 新工作份额: " +
                        newWorkingShare.toString().substring(0, Math.min(10, newWorkingShare.toString().length())) + "...");
            }
        }
    }

    /**
     * 基于扩展多项式重新生成主份额 - 严格遵循文档主份额定义
     */
    private void updateMainSharesForExtension(int newThreshold) {
        if (verbose) System.out.println("  重新计算 " + n + " 个参与者的主份额");

        for (int i = 0; i < n; i++) {
            BigInteger id = participantIDs.get(i);
            // 直接基于扩展后的多项式计算新主份额
            UnivariatePolynomial newMainShare = mainPolynomial.evaluateAtX(id);
            mainShares.set(i, newMainShare);

            if (verbose && i < 2) {
                System.out.println("    参与者 P" + (i+1) + " 新主份额阶数: " + (newMainShare.coefficients.length - 1));
            }
        }
    }

    /**
     * 直接构造扩展后的多项式 - 严格遵循文档4.4.1节数学描述
     * 核心：保持低阶系数不变，仅扩展高阶随机系数
     */
    private BivariatePolynomial buildExtendedPolynomialDirectly(int newThreshold) {
        // 创建新阈值对应的多项式
        BivariatePolynomial extendedPoly = new BivariatePolynomial(newThreshold, p, this.secret, false);

        // 步骤1: 复制原始多项式系数（低阶部分）
        if (verbose) System.out.println("  复制原始多项式低阶系数 (0 ≤ i,j < " + currentThreshold + ")");
        for (int i = 0; i < currentThreshold; i++) {
            for (int j = 0; j < currentThreshold; j++) {
                extendedPoly.setCoefficient(i, j, mainPolynomial.coefficients[i][j]);
            }
        }

        // 步骤2: 生成扩展的高阶随机系数 - 严格遵循文档扩展设计
        if (verbose) System.out.println("  生成扩展高阶随机系数 (" + currentThreshold + " ≤ i,j < " + newThreshold + ")");
        SecureRandom secureRandom = BCCryptoUtils.createSecureRandom(null);

        // 只生成扩展部分的高阶系数
        for (int i = currentThreshold; i < newThreshold; i++) {
            for (int j = i; j < newThreshold; j++) { // 只处理上三角，包括对角线
                BigInteger coeff = new BigInteger(p.bitLength() - 1, secureRandom).mod(p);
                extendedPoly.setCoefficient(i, j, coeff);
                if (i != j) {
                    extendedPoly.setCoefficient(j, i, coeff); // 保持对称性
                }

                if (verbose && i == currentThreshold && j == currentThreshold) {
                    System.out.println("  首个扩展系数: a[" + i + "][" + j + "] = " + coeff);
                }
            }
        }

        // 验证扩展后多项式的秘密保持性
        BigInteger verifiedSecret = extendedPoly.evaluate(BigInteger.ZERO, BigInteger.ZERO);
        if (!verifiedSecret.equals(secret)) {
            throw new IllegalStateException("多项式扩展后秘密值不匹配");
        }

        if (verbose) {
            System.out.println("  扩展多项式验证: f(0,0) = " + verifiedSecret + " ✓");
            System.out.println("  独立系数数量: " + (newThreshold * (newThreshold + 1) / 2) +
                    " (原系数: " + (currentThreshold * (currentThreshold + 1) / 2) + ")");
        }

        return extendedPoly;
    }

    /**
     * 生成扩展多项式 - 辅助方法
     */
    private BivariatePolynomial generateExtensionPolynomial(int k) {
        // 创建扩展多项式，常数项为0 - 严格遵循文档要求
        BivariatePolynomial extensionPoly = new BivariatePolynomial(currentThreshold + k, p, BigInteger.ZERO, false);

        // 只设置高阶系数，保持低阶系数为0 - 关键修复
        SecureRandom secureRandom = new SecureRandom();
        for (int i = currentThreshold; i <= currentThreshold + k - 1; i++) {
            for (int j = i; j <= currentThreshold + k - 1; j++) {
                BigInteger coeff = new BigInteger(p.bitLength() - 1, secureRandom).mod(p);
                extensionPoly.setCoefficient(i, j, coeff);
                if (i != j) {
                    extensionPoly.setCoefficient(j, i, coeff);
                }
            }
        }
        return extensionPoly;
    }

    /**
     * 构建扩展后的多项式 - 关键修复方法
     */
    private BivariatePolynomial buildExtendedPolynomial(BivariatePolynomial extensionPoly, int newThreshold) {
        BivariatePolynomial newPoly = new BivariatePolynomial(newThreshold, p, this.secret, false);

        // 复制原始多项式系数
        for (int i = 0; i < currentThreshold; i++) {
            for (int j = 0; j < currentThreshold; j++) {
                newPoly.setCoefficient(i, j, mainPolynomial.coefficients[i][j]);
            }
        }

        // 添加扩展多项式系数
        for (int i = 0; i < newThreshold; i++) {
            for (int j = 0; j < newThreshold; j++) {
                if (i >= currentThreshold || j >= currentThreshold) {
                    BigInteger current = newPoly.coefficients[i][j];
                    BigInteger extension = extensionPoly.coefficients[i][j];
                    newPoly.setCoefficient(i, j, current.add(extension).mod(p));
                }
            }
        }

        return newPoly;
    }

    /**
     * 更新主份额 - 辅助方法
     */
    private void updateMainShares(BivariatePolynomial extensionPoly) {
        for (int i = 0; i < n; i++) {
            BigInteger id = participantIDs.get(i);
            UnivariatePolynomial extensionShare = extensionPoly.evaluateAtX(id);
            UnivariatePolynomial newMainShare = mainShares.get(i).add(extensionShare);
            mainShares.set(i, newMainShare);
        }
    }

    /**
     * 更新工作份额 - 辅助方法
     */
    private void updateWorkingSharesForIncrease(BivariatePolynomial extensionPoly) {
        for (int i = 0; i < n; i++) {
            BigInteger extensionValue = extensionPoly.evaluate(participantIDs.get(i), BigInteger.ZERO);
            BigInteger newWorkingShare = workingShares.get(i).add(extensionValue).mod(p);
            workingShares.set(i, newWorkingShare);
        }
    }

    /**
     * 工作份额更新协议：严格按照文档4.5.1节实现
     */
    public void workingShareUpdate(String contextInfo, int updateRound) {
        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("4.5.1 工作份额更新协议开始");
            System.out.println("=".repeat(60));
        }

        // 步骤1: 生成公共随机种子 - 严格遵循文档步骤一
        BigInteger randomSeed = generateRandomSeed(contextInfo, updateRound);

        // 步骤2: 生成更新多项式 - 严格遵循文档步骤二
        BivariatePolynomial updatePoly = generateUpdatePolynomial(randomSeed, currentThreshold);

        // 步骤3: 更新本地工作份额 - 严格遵循文档步骤三
        updateWorkingSharesWithPoly(updatePoly);

        long endTime = System.nanoTime();
        stats.addWorkingShareUpdateTime(endTime - startTime);

        if (verbose) {
            System.out.println("✓ 工作份额更新完成");
            System.out.printf("工作份额更新总时间: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }
    }

    /**
     * 使用更新多项式更新工作份额 - 辅助方法
     */
    private void updateWorkingSharesWithPoly(BivariatePolynomial updatePoly) {
        for (int i = 0; i < n; i++) {
            BigInteger oldShare = workingShares.get(i);
            BigInteger updateValue = updatePoly.evaluate(participantIDs.get(i), BigInteger.ZERO);
            BigInteger newShare = oldShare.add(updateValue).mod(p);
            workingShares.set(i, newShare);
        }
    }

    /**
     * 主份额更新协议：严格按照文档4.5.2节实现
     */
    public void mainShareUpdate(String contextInfo, int updateRound) {
        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("4.5.2 主份额更新协议开始");
            System.out.println("=".repeat(60));
        }

        // 步骤1: 生成公共随机种子
        BigInteger randomSeed = generateRandomSeed(contextInfo, updateRound);

        // 步骤2: 生成更新多项式
        BivariatePolynomial updatePoly = generateUpdatePolynomial(randomSeed, currentMainThreshold);

        // 步骤3: 更新本地主份额
        updateMainSharesWithPoly(updatePoly);

        long endTime = System.nanoTime();
        stats.addMasterShareUpdateTime(endTime - startTime);

        if (verbose) {
            System.out.println("✓ 主份额更新完成");
            System.out.printf("主份额更新总时间: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }
    }

    /**
     * 使用更新多项式更新主份额 - 辅助方法
     */
    private void updateMainSharesWithPoly(BivariatePolynomial updatePoly) {
        for (int i = 0; i < n; i++) {
            UnivariatePolynomial oldMainShare = mainShares.get(i);
            UnivariatePolynomial updatePolyAtID = updatePoly.evaluateAtX(participantIDs.get(i));
            UnivariatePolynomial newMainShare = oldMainShare.add(updatePolyAtID);
            mainShares.set(i, newMainShare);
        }
    }

    /**
     * 基于工作份额的秘密恢复：严格按照文档4.6.1节实现
     */
    public BigInteger secretRecoveryFromWorkingShares(List<Integer> participantIndices) {
        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("4.6.1 基于工作份额的秘密恢复开始");
            System.out.println("=".repeat(60));
        }

        validateRecoveryParticipants(participantIndices, currentThreshold);

        // 预计算配对密钥
        Map<String, BigInteger> pairingKeyCache = precomputePairingKeys(participantIndices);

        // 计算拉格朗日分量
        List<BigInteger> lagrangeComponents = computeRecoveryLagrangeComponents(participantIndices, true);

        // 生成发布值
        List<BigInteger> publishedValues = generatePublishedValues(participantIndices, lagrangeComponents, pairingKeyCache);

        // 恢复秘密
        BigInteger recoveredSecret = recoverSecretFromPublishedValues(publishedValues);

        long endTime = System.nanoTime();
        stats.addWorkingSharesRecoveryTime(endTime - startTime);

        if (verbose) {
            printRecoveryResult(recoveredSecret, "工作份额");
            System.out.printf("恢复时间: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }

        return recoveredSecret;
    }

    /**
     * 基于主份额的秘密恢复：严格按照文档4.6.1节实现
     */
    public BigInteger secretRecoveryFromMainShares(List<Integer> participantIndices) {
        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("4.6.1 基于主份额的秘密恢复开始");
            System.out.println("=".repeat(60));
        }

        validateRecoveryParticipants(participantIndices, currentMainThreshold);

        // 预计算配对密钥
        Map<String, BigInteger> pairingKeyCache = precomputePairingKeys(participantIndices);

        // 计算拉格朗日分量（使用主份额）
        List<BigInteger> lagrangeComponents = computeRecoveryLagrangeComponents(participantIndices, false);

        // 生成发布值
        List<BigInteger> publishedValues = generatePublishedValues(participantIndices, lagrangeComponents, pairingKeyCache);

        // 恢复秘密
        BigInteger recoveredSecret = recoverSecretFromPublishedValues(publishedValues);

        long endTime = System.nanoTime();
        stats.addMainSharesRecoveryTime(endTime - startTime);

        if (verbose) {
            printRecoveryResult(recoveredSecret, "主份额");
            System.out.printf("恢复时间: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }

        return recoveredSecret;
    }

    /**
     * 验证恢复参与者 - 辅助方法
     */
    private void validateRecoveryParticipants(List<Integer> participantIndices, int requiredThreshold) {
        if (participantIndices.size() < requiredThreshold) {
            throw new IllegalArgumentException(
                    "参与者数量不足，需要至少 " + requiredThreshold + " 个参与者，当前: " + participantIndices.size());
        }
    }

    /**
     * 预计算配对密钥 - 辅助方法
     */
    private Map<String, BigInteger> precomputePairingKeys(List<Integer> participantIndices) {
        Map<String, BigInteger> pairingKeyCache = new HashMap<>();
        for (int i = 0; i < participantIndices.size(); i++) {
            int idx_i = participantIndices.get(i);
            BigInteger id_i = participantIDs.get(idx_i);
            for (int j = i + 1; j < participantIndices.size(); j++) {
                int idx_j = participantIndices.get(j);
                BigInteger id_j = participantIDs.get(idx_j);
                BigInteger pairingKey = mainPolynomial.evaluate(id_i, id_j);
                pairingKeyCache.put(idx_i + "_" + idx_j, pairingKey);
                pairingKeyCache.put(idx_j + "_" + idx_i, pairingKey);
            }
        }
        return pairingKeyCache;
    }

    /**
     * 计算恢复拉格朗日分量 - 辅助方法
     */
    private List<BigInteger> computeRecoveryLagrangeComponents(List<Integer> participantIndices, boolean useWorkingShares) {
        List<BigInteger> components = new ArrayList<>();
        for (int i = 0; i < participantIndices.size(); i++) {
            int idx = participantIndices.get(i);
            BigInteger lagrangeCoeff = computeLagrangeCoefficientForRecovery(idx, participantIndices);
            BigInteger shareValue = useWorkingShares ?
                    workingShares.get(idx) : mainShares.get(idx).evaluate(BigInteger.ZERO);
            BigInteger component = shareValue.multiply(lagrangeCoeff).mod(p);
            components.add(component);
        }
        return components;
    }

    /**
     * 生成发布值 - 辅助方法
     */
    private List<BigInteger> generatePublishedValues(List<Integer> participantIndices,
                                                     List<BigInteger> lagrangeComponents,
                                                     Map<String, BigInteger> pairingKeyCache) {
        List<BigInteger> publishedValues = new ArrayList<>();
        for (int i = 0; i < participantIndices.size(); i++) {
            int idx_i = participantIndices.get(i);
            BigInteger component = lagrangeComponents.get(i);
            BigInteger publishedValue = component;

            for (int j = 0; j < participantIndices.size(); j++) {
                if (i != j) {
                    int idx_j = participantIndices.get(j);
                    BigInteger id_i = participantIDs.get(idx_i);
                    BigInteger id_j = participantIDs.get(idx_j);
                    String key = idx_i + "_" + idx_j;
                    BigInteger pairingKey = pairingKeyCache.get(key);

                    if (id_i.compareTo(id_j) > 0) {
                        publishedValue = publishedValue.subtract(pairingKey).mod(p);
                    } else {
                        publishedValue = publishedValue.add(pairingKey).mod(p);
                    }
                }
            }
            publishedValues.add(publishedValue);
        }
        return publishedValues;
    }

    /**
     * 从发布值恢复秘密 - 辅助方法
     */
    private BigInteger recoverSecretFromPublishedValues(List<BigInteger> publishedValues) {
        BigInteger recoveredSecret = BigInteger.ZERO;
        for (BigInteger value : publishedValues) {
            recoveredSecret = recoveredSecret.add(value).mod(p);
        }
        return recoveredSecret;
    }

    /**
     * 打印恢复结果 - 辅助方法
     */
    private void printRecoveryResult(BigInteger recoveredSecret, String shareType) {
        System.out.println("✓ 基于" + shareType + "的秘密恢复完成");
        System.out.printf("恢复的秘密: %s\n", recoveredSecret);
        System.out.printf("原始的秘密: %s\n", secret);
        System.out.println("恢复结果: " + (recoveredSecret.equals(secret) ? "✓ 成功" : "✗ 失败"));
    }

    // ============================ 工具方法 ============================

    /**
     * 计算拉格朗日系数（用于阈值调整）
     */
    private BigInteger computeLagrangeCoefficient(int index, int threshold) {
        BigInteger numerator = BigInteger.ONE;
        BigInteger denominator = BigInteger.ONE;
        BigInteger xi = participantIDs.get(index);

        for (int j = 0; j < threshold; j++) {
            if (j != index) {
                BigInteger xj = participantIDs.get(j);
                numerator = numerator.multiply(BigInteger.ZERO.subtract(xj)).mod(p);
                denominator = denominator.multiply(xi.subtract(xj)).mod(p);
            }
        }

        return numerator.multiply(denominator.modInverse(p)).mod(p);
    }

    /**
     * 计算恢复时的拉格朗日系数
     */
    private BigInteger computeLagrangeCoefficientForRecovery(int index, List<Integer> indices) {
        BigInteger numerator = BigInteger.ONE;
        BigInteger denominator = BigInteger.ONE;
        BigInteger xi = participantIDs.get(index);

        for (int j : indices) {
            if (j != index) {
                BigInteger xj = participantIDs.get(j);
                numerator = numerator.multiply(BigInteger.ZERO.subtract(xj)).mod(p);
                denominator = denominator.multiply(xi.subtract(xj)).mod(p);
            }
        }

        return numerator.multiply(denominator.modInverse(p)).mod(p);
    }

    /**
     * 生成随机种子：严格按照文档4.5.1节步骤一实现
     */
    private BigInteger generateRandomSeed(String contextInfo, int round) {
        try {
            // 使用 Bouncy Castle 的 SHA-256
            String input = previousSeed.toString() + contextInfo + round;
            byte[] hash = BCCryptoUtils.sha256(input.getBytes());
            BigInteger newSeed = new BigInteger(1, hash).mod(p);
            previousSeed = newSeed;

            if (verbose) {
                System.out.println("  生成随机种子: " + newSeed.toString().substring(0, 20) + "...");
            }

            return newSeed;
        } catch (Exception e) {
            // 备选方案：使用 Java 内置的 SHA-256
            System.err.println("Bouncy Castle SHA-256 失败，使用 Java 内置实现: " + e.getMessage());
            try {
                java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
                String input = previousSeed.toString() + contextInfo + round;
                byte[] hash = digest.digest(input.getBytes());
                BigInteger newSeed = new BigInteger(1, hash).mod(p);
                previousSeed = newSeed;
                return newSeed;
            } catch (Exception ex) {
                throw new RuntimeException("随机种子生成失败", ex);
            }
        }
    }

    /**
     * 生成更新多项式：严格按照文档4.5.1节步骤二实现
     */
    private BivariatePolynomial generateUpdatePolynomial(BigInteger seed, int threshold) {
        SecureRandom prng = BCCryptoUtils.createSecureRandom(seed.toByteArray());
        BivariatePolynomial updatePoly = new BivariatePolynomial(threshold, p, BigInteger.ZERO, false);

        // 显式设置常数项为0
        updatePoly.setCoefficient(0, 0, BigInteger.ZERO);

        // 生成对称系数
        for (int i = 0; i < threshold; i++) {
            for (int j = i; j < threshold; j++) {
                if (i == 0 && j == 0) continue;
                // 使用 Bouncy Castle 的安全随机数生成
                BigInteger coeff = BCCryptoUtils.generateSecureRandomBigInteger(p, prng);
                updatePoly.setCoefficient(i, j, coeff);
                if (i != j) {
                    updatePoly.setCoefficient(j, i, coeff);
                }
            }
        }

        return updatePoly;
    }

    /**
     * 性能统计类
     */
    public static class PerformanceStats {
        private List<Long> initTimes = new ArrayList<>();
        private List<Long> thresholdAdjustTimes = new ArrayList<>();
        private List<Long> thresholdIncreaseTimes = new ArrayList<>();
        private List<Long> workingShareUpdateTimes = new ArrayList<>();
        private List<Long> masterShareUpdateTimes = new ArrayList<>();
        private List<Long> workingSharesRecoveryTimes = new ArrayList<>();
        private List<Long> mainSharesRecoveryTimes = new ArrayList<>();
        private List<Long> mixedScenarioTimes = new ArrayList<>();

        public void addInitTime(long time) { initTimes.add(time); }
        public void addThresholdAdjustTime(long time) { thresholdAdjustTimes.add(time); }
        public void addThresholdIncreaseTime(long time) { thresholdIncreaseTimes.add(time); }
        public void addWorkingShareUpdateTime(long time) { workingShareUpdateTimes.add(time); }
        public void addMasterShareUpdateTime(long time) { masterShareUpdateTimes.add(time); }
        public void addWorkingSharesRecoveryTime(long time) { workingSharesRecoveryTimes.add(time); }
        public void addMainSharesRecoveryTime(long time) { mainSharesRecoveryTimes.add(time); }
        public void addMixedScenarioTime(long time) { mixedScenarioTimes.add(time); }

        /**
         * 打印性能统计结果
         */
        public void printStats() {
            System.out.println("\n" + "=".repeat(80));
            System.out.println("性能统计 (" + initTimes.size() + " 次实验)");
            System.out.println("=".repeat(80));

            if (!initTimes.isEmpty()) System.out.printf("系统初始化平均时间: %.3f ms (标准差: %.3f ms)\n",
                    calculateAverage(initTimes) / 1e6, calculateStdDev(initTimes) / 1e6);
            if (!thresholdAdjustTimes.isEmpty()) System.out.printf("阈值下调平均时间: %.3f ms (标准差: %.3f ms)\n",
                    calculateAverage(thresholdAdjustTimes) / 1e6, calculateStdDev(thresholdAdjustTimes) / 1e6);
            if (!thresholdIncreaseTimes.isEmpty()) System.out.printf("阈值上调平均时间: %.3f ms (标准差: %.3f ms)\n",
                    calculateAverage(thresholdIncreaseTimes) / 1e6, calculateStdDev(thresholdIncreaseTimes) / 1e6);
            if (!workingShareUpdateTimes.isEmpty()) System.out.printf("工作份额更新平均时间: %.3f ms (标准差: %.3f ms)\n",
                    calculateAverage(workingShareUpdateTimes) / 1e6, calculateStdDev(workingShareUpdateTimes) / 1e6);
            if (!masterShareUpdateTimes.isEmpty()) System.out.printf("主份额更新平均时间: %.3f ms (标准差: %.3f ms)\n",
                    calculateAverage(masterShareUpdateTimes) / 1e6, calculateStdDev(masterShareUpdateTimes) / 1e6);
            if (!workingSharesRecoveryTimes.isEmpty()) System.out.printf("基于工作份额的秘密恢复平均时间: %.3f ms (标准差: %.3f ms)\n",
                    calculateAverage(workingSharesRecoveryTimes) / 1e6, calculateStdDev(workingSharesRecoveryTimes) / 1e6);
            if (!mainSharesRecoveryTimes.isEmpty()) System.out.printf("基于主份额的秘密恢复平均时间: %.3f ms (标准差: %.3f ms)\n",
                    calculateAverage(mainSharesRecoveryTimes) / 1e6, calculateStdDev(mainSharesRecoveryTimes) / 1e6);
            if (!mixedScenarioTimes.isEmpty()) System.out.printf("混合场景总平均时间: %.3f ms (标准差: %.3f ms)\n",
                    calculateAverage(mixedScenarioTimes) / 1e6, calculateStdDev(mixedScenarioTimes) / 1e6);


            System.out.println("\n时间分布 (ms):");
            System.out.printf("初始化: %s\n", formatTimeStats(initTimes));
            System.out.printf("阈值下调: %s\n", formatTimeStats(thresholdAdjustTimes));
            System.out.printf("阈值上调: %s\n", formatTimeStats(thresholdIncreaseTimes));
            System.out.printf("工作份额更新: %s\n", formatTimeStats(workingShareUpdateTimes));
            System.out.printf("主份额更新: %s\n", formatTimeStats(masterShareUpdateTimes));
            System.out.printf("工作份额恢复: %s\n", formatTimeStats(workingSharesRecoveryTimes));
            System.out.printf("主份额恢复: %s\n", formatTimeStats(mainSharesRecoveryTimes));
            System.out.printf("混合场景: %s\n", formatTimeStats(mixedScenarioTimes));
        }

        private double calculateAverage(List<Long> times) {
            return times.stream().mapToLong(Long::longValue).average().orElse(0);
        }

        private double calculateStdDev(List<Long> times) {
            double average = calculateAverage(times);
            double variance = times.stream()
                    .mapToDouble(time -> Math.pow(time - average, 2))
                    .average().orElse(0);
            return Math.sqrt(variance);
        }

        private String formatTimeStats(List<Long> times) {
            if (times.isEmpty()) return "无数据";
            long min = times.stream().mapToLong(Long::longValue).min().orElse(0);
            long max = times.stream().mapToLong(Long::longValue).max().orElse(0);
            double avg = calculateAverage(times);
            return String.format("min=%.3f, avg=%.3f, max=%.3f",
                    min / 1e6, avg / 1e6, max / 1e6);
        }

        /**
         * 合并统计结果
         */
        public void merge(PerformanceStats other) {
            this.initTimes.addAll(other.initTimes);
            this.thresholdAdjustTimes.addAll(other.thresholdAdjustTimes);
            this.thresholdIncreaseTimes.addAll(other.thresholdIncreaseTimes);
            this.workingShareUpdateTimes.addAll(other.workingShareUpdateTimes);
            this.masterShareUpdateTimes.addAll(other.masterShareUpdateTimes);
            this.workingSharesRecoveryTimes.addAll(other.workingSharesRecoveryTimes);
            this.mainSharesRecoveryTimes.addAll(other.mainSharesRecoveryTimes);
            this.mixedScenarioTimes.addAll(other.mixedScenarioTimes);
        }
    }

    /**
     * 双变量多项式类：表示对称双变量多项式
     * 对应文档4.2节双变量多项式定义
     */
    private static class BivariatePolynomial {
        private int degree;
        private BigInteger p;
        public BigInteger[][] coefficients;

        /**
         * 构造函数：创建双变量多项式
         */
        public BivariatePolynomial(int threshold, BigInteger p, BigInteger constantTerm, boolean verbose) {
            this.degree = threshold - 1;
            this.p = p;
            this.coefficients = new BigInteger[threshold][threshold];

            // 初始化所有系数为0
            for (int i = 0; i < threshold; i++) {
                for (int j = 0; j < threshold; j++) {
                    coefficients[i][j] = BigInteger.ZERO;
                }
            }

            // 设置常数项为秘密值
            coefficients[0][0] = constantTerm.mod(p);
            if (verbose) {
                System.out.println("  常数项 a_00 = " + constantTerm + " (秘密值)");
            }

            // 使用 Bouncy Castle 的安全随机数生成器
            SecureRandom secureRandom = BCCryptoUtils.createSecureRandom(null);
            int coefficientCount = 0;

            // 只生成下三角部分（包括对角线），然后对称复制到上三角
            for (int i = 0; i < threshold; i++) {
                for (int j = i; j < threshold; j++) {
                    if (i == 0 && j == 0) continue; // 常数项已设置

                    // 使用安全随机数生成
                    BigInteger coeff = new BigInteger(p.bitLength() - 1, secureRandom).mod(p);

                    coefficients[i][j] = coeff;
                    if (i != j) {
                        coefficients[j][i] = coeff; // 严格对称性
                    }
                    coefficientCount++;
                }
            }

            if (verbose) {
                System.out.println("  共生成 " + coefficientCount + " 个随机系数");
            }
        }

        public void setCoefficient(int i, int j, BigInteger value) {
            coefficients[i][j] = value.mod(p);
        }

        /**
         * 计算多项式在给定点(x,y)的值
         * 对应文档4.2节多项式求值
         */
        public BigInteger evaluate(BigInteger x, BigInteger y) {
            BigInteger result = BigInteger.ZERO;
            for (int i = 0; i <= degree; i++) {
                for (int j = 0; j <= degree; j++) {
                    BigInteger term = coefficients[i][j]
                            .multiply(x.pow(i))
                            .multiply(y.pow(j))
                            .mod(p);
                    result = result.add(term).mod(p);
                }
            }
            return result;
        }

        /**
         * 在给定x值下计算多项式，得到关于y的单变量多项式
         * 对应文档4.3.1节主份额计算
         */
        public UnivariatePolynomial evaluateAtX(BigInteger x) {
            BigInteger[] newCoeffs = new BigInteger[degree + 1];
            for (int j = 0; j <= degree; j++) {
                BigInteger coeff = BigInteger.ZERO;
                for (int i = 0; i <= degree; i++) {
                    BigInteger term = coefficients[i][j].multiply(x.pow(i)).mod(p);
                    coeff = coeff.add(term).mod(p);
                }
                newCoeffs[j] = coeff;
            }
            return new UnivariatePolynomial(newCoeffs, p);
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("f(x,y) = ");
            boolean firstTerm = true;

            for (int i = 0; i <= degree; i++) {
                for (int j = 0; j <= degree; j++) {
                    if (coefficients[i][j].compareTo(BigInteger.ZERO) != 0) {
                        if (!firstTerm) {
                            sb.append(" + ");
                        }
                        sb.append(coefficients[i][j]);
                        if (i > 0) sb.append("x^").append(i);
                        if (j > 0) sb.append("y^").append(j);
                        firstTerm = false;
                    }
                }
            }
            sb.append(" mod ").append(p);
            return sb.toString();
        }
    }

    /**
     * 单变量多项式类：表示关于y的单变量多项式
     * 对应文档4.3.1节主份额定义
     */
    private static class UnivariatePolynomial {
        private BigInteger[] coefficients;
        private BigInteger p;

        public UnivariatePolynomial(BigInteger[] coefficients, BigInteger p) {
            this.coefficients = coefficients;
            this.p = p;
        }

        /**
         * 计算多项式在给定y值下的结果
         */
        public BigInteger evaluate(BigInteger y) {
            BigInteger result = BigInteger.ZERO;
            for (int i = 0; i < coefficients.length; i++) {
                BigInteger term = coefficients[i].multiply(y.pow(i)).mod(p);
                result = result.add(term).mod(p);
            }
            return result;
        }

        /**
         * 多项式加法
         * 对应文档4.5.2节主份额更新
         */
        public UnivariatePolynomial add(UnivariatePolynomial other) {
            int maxLength = Math.max(coefficients.length, other.coefficients.length);
            BigInteger[] newCoeffs = new BigInteger[maxLength];

            for (int i = 0; i < maxLength; i++) {
                BigInteger coeff1 = (i < coefficients.length) ? coefficients[i] : BigInteger.ZERO;
                BigInteger coeff2 = (i < other.coefficients.length) ? other.coefficients[i] : BigInteger.ZERO;
                newCoeffs[i] = coeff1.add(coeff2).mod(p);
            }

            return new UnivariatePolynomial(newCoeffs, p);
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("S(y) = ");
            boolean firstTerm = true;

            for (int i = 0; i < coefficients.length; i++) {
                if (coefficients[i].compareTo(BigInteger.ZERO) != 0) {
                    if (!firstTerm) {
                        sb.append(" + ");
                    }
                    sb.append(coefficients[i]);
                    if (i > 0) {
                        sb.append("y");
                        if (i > 1) sb.append("^").append(i);
                    }
                    firstTerm = false;
                }
            }
            sb.append(" mod ").append(p);
            return sb.toString();
        }
    }

    /**
     * 阈值测试任务类
     */
    private static class ThresholdTestTask implements Callable<ThresholdTestResult> {
        private final int threshold;
        private final int numExperiments;
        private final boolean verbose;
        private final String testType;

        public ThresholdTestTask(int threshold, int numExperiments, boolean verbose, String testType) {
            this.threshold = threshold;
            this.numExperiments = numExperiments;
            this.verbose = verbose;
            this.testType = testType;
        }

        @Override
        public ThresholdTestResult call() {
            String threadName = Thread.currentThread().getName();
            PerformanceStats threadStats = new PerformanceStats();
            int successCount = 0;
            int failureCount = 0;

            System.out.printf("[%s] 开始测试阈值 t=%d (%d 次实验, 测试类型: %s)\n",
                    threadName, threshold, numExperiments, testType);

            for (int exp = 0; exp < numExperiments; exp++) {
                try {
                    boolean expVerbose = verbose && (exp == 0); // 每个线程只输出第一次实验的详细日志

                    // 创建系统实例
                    DynamicThresholdSecretSharingVersion7App system = new DynamicThresholdSecretSharingVersion7App(
                            NUM_PARTICIPANTS, threshold, expVerbose);

                    // 1. 系统初始化
                    system.systemInitialization(system.secret);

                    // 根据测试类型执行不同的操作序列
                    switch (testType) {
                        case "basic":
                            // 基础测试：下调 + 份额更新 + 两种恢复方式验证
                            int tempthreshold = threshold - 3;
                            if (tempthreshold >= 2) {
                                system.thresholdDecrease(tempthreshold);
                            }
                            system.workingShareUpdate("test_update", 1);
                            system.mainShareUpdate("test_update", 1);
                            break;

                        case "increase":
                            // 阈值上调测试
                            if (expVerbose) {
                                System.out.println("\n=== 阈值上调测试开始 ===");
                            }
                            /*for (int k = 1; k <= 5; k++) {
                                int newThreshold = threshold + k;
                                if (newThreshold <= system.n) {
                                    system.thresholdIncrease(newThreshold);
                                }
                            }*/
                            int newThreshold = threshold + INCREASE_THRESHOLDS;
                            if (newThreshold <= system.n) {
                                system.thresholdIncrease(newThreshold);
                            }
                            break;

                        case "mixed":
                            // 混合场景测试：上调 -> 工作份额更新 -> 下调 -> 主份额更新
                            if (expVerbose) {
                                System.out.println("\n=== 混合场景测试开始 ===");
                            }
                            long mixedTotalStart = System.nanoTime();

                            if (threshold <= system.n) {
                                int originalThreshold = threshold;

                                // 1. 阈值上调
                                int maxThreshold = threshold + INCREASE_THRESHOLDS;
                                system.thresholdIncrease(maxThreshold);

                                // 2. 工作份额更新
                                system.workingShareUpdate("mixed_scenario", 1);

                                // 3. 阈值下调
                                system.thresholdDecrease(originalThreshold);

                                // 4. 主份额更新
                                system.mainShareUpdate("mixed_scenario", 1);
                            }

                            long mixedTotalEnd = System.nanoTime();
                            threadStats.addMixedScenarioTime(mixedTotalEnd - mixedTotalStart);
                            break;
                    }

                    // 秘密恢复验证
                    List<Integer> recoveryParticipants = new ArrayList<>();
                    for (int i = 0; i < system.currentThreshold && i < system.n; i++) {
                        recoveryParticipants.add(i);
                    }

                    List<Integer> recoveryMainParticipants = new ArrayList<>();
                    for (int i = 0; i < system.currentMainThreshold && i < system.n; i++) {
                        recoveryMainParticipants.add(i);
                    }

                    BigInteger recoveredFromWorking = system.secretRecoveryFromWorkingShares(recoveryParticipants);
                    BigInteger recoveredFromMain = system.secretRecoveryFromMainShares(recoveryMainParticipants);

                    // 验证恢复的正确性
                    if (!recoveredFromWorking.equals(system.secret) || !recoveredFromMain.equals(system.secret)) {
                        failureCount++;
                        if (expVerbose) {
                            System.out.println("恢复失败！工作份额恢复: " + recoveredFromWorking +
                                    ", 主份额恢复: " + recoveredFromMain +
                                    ", 期望: " + system.secret);
                        }
                    } else {
                        successCount++;
                    }

                    // 收集统计信息
                    if (!system.stats.initTimes.isEmpty()) {
                        threadStats.addInitTime(system.stats.initTimes.get(0));
                    }
                    if (system.stats.thresholdAdjustTimes.size() > 0) {
                        threadStats.addThresholdAdjustTime(system.stats.thresholdAdjustTimes.get(0));
                    }
                    if (system.stats.thresholdIncreaseTimes.size() > 0) {
                        threadStats.addThresholdIncreaseTime(system.stats.thresholdIncreaseTimes.get(0));
                    }
                    if (system.stats.workingShareUpdateTimes.size() > 0) {
                        threadStats.addWorkingShareUpdateTime(system.stats.workingShareUpdateTimes.get(0));
                    }
                    if (system.stats.masterShareUpdateTimes.size() > 0) {
                        threadStats.addMasterShareUpdateTime(system.stats.masterShareUpdateTimes.get(0));
                    }
                    if (system.stats.workingSharesRecoveryTimes.size() > 0) {
                        threadStats.addWorkingSharesRecoveryTime(system.stats.workingSharesRecoveryTimes.get(0));
                    }
                    if (system.stats.mainSharesRecoveryTimes.size() > 0) {
                        threadStats.addMainSharesRecoveryTime(system.stats.mainSharesRecoveryTimes.get(0));
                    }

                } catch (Exception e) {
                    System.out.printf("[%s] 实验 %d (阈值 t=%d, 类型: %s) 失败: %s\n",
                            threadName, exp + 1, threshold, testType, e.getMessage());
                    failureCount++;
                }
            }

            System.out.printf("[%s] 阈值 t=%d (类型: %s) 测试完成: %d 成功, %d 失败\n",
                    threadName, threshold, testType, successCount, failureCount);

            return new ThresholdTestResult(threshold, threadStats, successCount, failureCount, testType);
        }
    }

    /**
     * 阈值测试结果类
     */
    private static class ThresholdTestResult {
        final int threshold;
        final PerformanceStats stats;
        final int successCount;
        final int failureCount;
        final String testType;

        public ThresholdTestResult(int threshold, PerformanceStats stats, int successCount, int failureCount, String testType) {
            this.threshold = threshold;
            this.stats = stats;
            this.successCount = successCount;
            this.failureCount = failureCount;
            this.testType = testType;
        }
    }
    /**
     * 主方法：程序入口点
     */
    public static void main(String[] args) {
        System.out.println("开始动态阈值秘密共享系统性能测试（严格遵循文档方案）...");
        System.out.println("参数设置: n=" + NUM_PARTICIPANTS + ", 阈值=" + Arrays.toString(THRESHOLDS));
        System.out.println("实验次数: " + NUM_EXPERIMENTS);
        System.out.println("素数位数: " + PRIME_BIT_LENGTH);
        System.out.println("线程池大小: " + THREAD_POOL_SIZE);
        System.out.println();

        // 创建线程池
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
        List<Future<ThresholdTestResult>> futures = new ArrayList<>();
        Map<String, Map<Integer, PerformanceStats>> testTypeStats = new ConcurrentHashMap<>();
        Map<String, Map<Integer, Integer>> successCounts = new ConcurrentHashMap<>();
        Map<String, Map<Integer, Integer>> failureCounts = new ConcurrentHashMap<>();

        // 初始化统计映射
        String[] testTypes = {"basic", "increase", "mixed"};
        for (String testType : testTypes) {
            testTypeStats.put(testType, new ConcurrentHashMap<>());
            successCounts.put(testType, new ConcurrentHashMap<>());
            failureCounts.put(testType, new ConcurrentHashMap<>());

            for (int threshold : THRESHOLDS) {
                testTypeStats.get(testType).put(threshold, new PerformanceStats());
                successCounts.get(testType).put(threshold, 0);
                failureCounts.get(testType).put(threshold, 0);
            }
        }

        System.out.println("启动多线程测试...");
        long startTime = System.currentTimeMillis();

        // 为每个阈值和测试类型提交测试任务
        for (String testType : testTypes) {
            for (int threshold : THRESHOLDS) {
                Future<ThresholdTestResult> future = executor.submit(
                        new ThresholdTestTask(threshold, NUM_EXPERIMENTS, false, testType)
                );
                futures.add(future);
            }
        }

        // 等待所有任务完成并收集结果
        for (Future<ThresholdTestResult> future : futures) {
            try {
                ThresholdTestResult result = future.get();
                testTypeStats.get(result.testType).get(result.threshold).merge(result.stats);
                successCounts.get(result.testType).put(result.threshold, result.successCount);
                failureCounts.get(result.testType).put(result.threshold, result.failureCount);
            } catch (Exception e) {
                System.out.println("任务执行异常: " + e.getMessage());
            }
        }

        long endTime = System.currentTimeMillis();
        executor.shutdown();

        System.out.printf("\n所有测试完成! 总执行时间: %.3f 秒\n", (endTime - startTime) / 1000.0);

        // 输出总体统计
        System.out.println("\n" + "=".repeat(80));
        System.out.println("总体性能统计");
        System.out.println("=".repeat(80));

        for (String testType : testTypes) {
            System.out.println("\n测试类型: " + testType);
            for (int threshold : THRESHOLDS) {
                if (testTypeStats.get(testType).get(threshold).initTimes.isEmpty()) {
                    continue;
                }

                System.out.println("\n阈值 t=" + threshold + ":");
                System.out.printf("成功率: %d/%d (%.2f%%)\n",
                        successCounts.get(testType).get(threshold),
                        NUM_EXPERIMENTS,
                        (successCounts.get(testType).get(threshold) * 100.0 / NUM_EXPERIMENTS));
                testTypeStats.get(testType).get(threshold).printStats();
            }
        }

        // 生成图表数据摘要
        generateChartSummary(mergeAllTestData(testTypeStats));

        System.out.println("\n所有测试完成!");
    }

    /**
     * 合并所有测试类型的数据
     */
    private static Map<Integer, PerformanceStats> mergeAllTestData(Map<String, Map<Integer, PerformanceStats>> testTypeStats) {
        Map<Integer, PerformanceStats> mergedStats = new TreeMap<>();

        for (int threshold : THRESHOLDS) {
            mergedStats.put(threshold, new PerformanceStats());
        }

        for (String testType : testTypeStats.keySet()) {
            Map<Integer, PerformanceStats> typeStats = testTypeStats.get(testType);
            for (int threshold : typeStats.keySet()) {
                if (mergedStats.containsKey(threshold)) {
                    mergedStats.get(threshold).merge(typeStats.get(threshold));
                }
            }
        }

        return mergedStats;
    }

    /**
     * 生成图表数据摘要
     */
    private static void generateChartSummary(Map<Integer, PerformanceStats> statsMap) {
        System.out.println("\n" + "=".repeat(120));
        System.out.println("图表数据摘要 (包含所有核心操作的计算开销)");
        System.out.println("=".repeat(120));

        Map<Integer, Map<String, Double>> chartData = new TreeMap<>();

        System.out.println("\n阈值(t) | 系统初始化(ms) | 阈值下调(ms) | 阈值上调(ms) | 工作份额更新(ms) | 主份额更新(ms) | 工作份额恢复(ms) | 主份额恢复(ms) | 混合场景(ms)");
        System.out.println("--------|---------------|-------------|-------------|-----------------|---------------|-----------------|---------------|-------------");

        for (int threshold : THRESHOLDS) {
            if (!statsMap.containsKey(threshold)) continue;
            Map<String, Double> tData = new HashMap<>();

            PerformanceStats stats = statsMap.get(threshold);

            double initTime = stats.calculateAverage(stats.initTimes) / 1e6;
            double thresholdTime = stats.thresholdAdjustTimes.isEmpty() ? 0 : stats.calculateAverage(stats.thresholdAdjustTimes) / 1e6;
            double thresholdIncreaseTime = stats.thresholdIncreaseTimes.isEmpty() ? 0 : stats.calculateAverage(stats.thresholdIncreaseTimes) / 1e6;
            double workingUpdateTime = stats.workingShareUpdateTimes.isEmpty() ? 0 : stats.calculateAverage(stats.workingShareUpdateTimes) / 1e6;
            double masterUpdateTime = stats.masterShareUpdateTimes.isEmpty() ? 0 : stats.calculateAverage(stats.masterShareUpdateTimes) / 1e6;
            double workingRecoveryTime = stats.workingSharesRecoveryTimes.isEmpty() ? 0 : stats.calculateAverage(stats.workingSharesRecoveryTimes) / 1e6;
            double mainRecoveryTime = stats.mainSharesRecoveryTimes.isEmpty() ? 0 : stats.calculateAverage(stats.mainSharesRecoveryTimes) / 1e6;
            double mixedScenarioTime = stats.mixedScenarioTimes.isEmpty() ? 0 : stats.calculateAverage(stats.mixedScenarioTimes) / 1e6;

            tData.put("系统初始化(ms)", initTime);
            tData.put("阈值下调(ms)", thresholdTime);
            tData.put("阈值上调(ms)", thresholdIncreaseTime);
            tData.put("工作份额更新(ms)", workingUpdateTime);
            tData.put("主份额更新(ms)", masterUpdateTime);
            tData.put("工作份额恢复(ms)", workingRecoveryTime);
            tData.put("主份额恢复(ms)", mainRecoveryTime);
            tData.put("混合场景(ms)", mixedScenarioTime);
            chartData.put(threshold, tData);

            System.out.printf("   %d    |     %7.3f   |   %7.3f   |   %7.3f   |      %7.3f    |     %7.3f   |      %7.3f    |     %7.3f   |   %7.3f\n",
                    threshold, initTime, thresholdTime, thresholdIncreaseTime,
                    workingUpdateTime, masterUpdateTime, workingRecoveryTime, mainRecoveryTime, mixedScenarioTime);
        }

        System.out.println("\n计算开销分析:");
        System.out.println("- 系统初始化: O(t²)多项式生成 + O(n·t²)主份额计算 + O(n)工作份额计算");
        System.out.println("- 阈值下调: O(t³)拉格朗日计算 + O(t·t'²)重共享多项式 + O(n·t²)加密 + O(n²·t)解密");
        System.out.println("- 阈值上调: O(t'²)扩展多项式 + O(n·t'²)份额更新");
        System.out.println("- 工作份额更新: O(t²)多项式生成 + O(n·t)份额更新");
        System.out.println("- 主份额更新: O(t²)多项式生成 + O(n·t²)主份额更新");
        System.out.println("- 秘密恢复: O(t²)拉格朗日插值");

        // 简化的图表生成
        SwingUtilities.invokeLater(() -> {
            generatePerformanceChart(chartData);
        });
    }

    /**
     * 绘制性能曲线图
     */
    public static void generatePerformanceChart(Map<Integer, Map<String, Double>> chartData) {
        // 创建简化版图表
        JFrame frame = new JFrame("核心操作执行时间随阈值变化趋势");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        PerformanceChart chart = new PerformanceChart();
        chart.setPerformanceData(chartData);
        frame.add(chart);

        frame.setSize(800, 600);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);

        // 保存图表
        chart.createAndSaveChart(chartData, "PerformanceChart.png");
    }
}