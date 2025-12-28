import javax.swing.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;

/**
 * 动态阈值秘密共享系统版本2应用程序
 * 支持阈值上调、下调、份额更新和秘密恢复等核心功能
 * 包含完整的性能测试和多线程实验框架
 */
public class DynamicThresholdSecretSharingVersion2App {
    // 实验参数配置
    private static final int NUM_PARTICIPANTS = 10;                    // 参与者数量
    private static final int[] THRESHOLDS = {4, 5, 6, 7};    // 测试的阈值范围
    private static final int NUM_EXPERIMENTS = 10000;                  // 每个阈值的实验次数
    private static final int PRIME_BIT_LENGTH = 256;                   // 素数位长度
    private static final int[] EXTENSION_ORDERS = {1, 2, 3};           // 阈值上调的扩展阶数

    // 预定义的256位大素数（符合素数性质，可直接使用）
    private static final BigInteger FIXED_256BIT_PRIME = new BigInteger(
            "115792089237316195423570985008687907853269984665640564039457584007908834671663");

    // 线程池配置
    private static final int THREAD_POOL_SIZE = THRESHOLDS.length;
    private static final int WARMUP_COUNT = 5;

    // 系统状态变量
    private BigInteger p;                          // 256位大素数
    private int n;                                // 参与者数量
    private int currentThreshold;                 // 当前阈值
    public BigInteger secret;                     // 秘密值
    private List<BigInteger> participantIDs;      // 参与者ID列表
    private BigInteger previousSeed;              // 初始随机数种子

    // 系统核心组件
    private BivariatePolynomial mainPolynomial;   // 主多项式
    private List<UnivariatePolynomial> mainShares; // 主份额
    private List<BigInteger> workingShares;       // 工作份额

    // 性能统计和输出控制
    private PerformanceStats stats;
    private boolean verbose;                      // 控制详细日志输出

    /**
     * 构造函数：初始化动态阈值秘密共享系统
     * @param n 参与者数量
     * @param initialThreshold 初始阈值
     * @param verbose 是否输出详细日志
     */
    public DynamicThresholdSecretSharingVersion2App(int n, int initialThreshold, boolean verbose) {
        this.n = n;
        this.currentThreshold = initialThreshold;
        this.p = FIXED_256BIT_PRIME;  // 使用预定义的固定素数
        this.participantIDs = generateParticipantIDs(n);
        this.stats = new PerformanceStats();
        this.verbose = verbose;
        // 使用固定的秘密值和初始种子，确保实验可重复性
        this.secret = new BigInteger("73138218979700741375608676119062004991785096625092157987592068860966427730354").mod(p);
        this.previousSeed = new BigInteger("10101010");
    }

    /**
     * 生成参与者ID列表
     * @param n 参与者数量
     * @return 参与者ID列表，使用1到n的整数作为ID
     */
    private List<BigInteger> generateParticipantIDs(int n) {
        List<BigInteger> ids = new ArrayList<>();
        for (int i = 1; i <= n; i++) {
            ids.add(BigInteger.valueOf(i));
        }
        return ids;
    }

    /**
     * 系统初始化：设置秘密值并生成主多项式、主份额和工作份额
     * @param secret 要保护的秘密值
     */
    public void systemInitialization(BigInteger secret) {
        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n=== 系统初始化开始 ===");
            System.out.println("秘密值 s = " + secret);
            System.out.println("有限域 GF(p), p = " + p);
            System.out.println("参与者数量 n = " + n);
            System.out.println("初始阈值 t = " + currentThreshold);
            System.out.println("多项式系数数量: " + (currentThreshold * (currentThreshold + 1) / 2));
        }

        this.secret = secret;

        // 生成对称双变量多项式
        long polyStart = System.nanoTime();
        this.mainPolynomial = new BivariatePolynomial(currentThreshold, p, secret, verbose);
        long polyEnd = System.nanoTime();

        if (verbose) {
            System.out.println("\n生成的主多项式:");
            System.out.println(mainPolynomial.toString());
            System.out.printf("多项式生成时间: %.3f ms\n", (polyEnd - polyStart) / 1e6);
        }

        // 生成主份额
        long shareStart = System.nanoTime();
        this.mainShares = new ArrayList<>();
        for (int i = 0; i < participantIDs.size(); i++) {
            BigInteger id = participantIDs.get(i);
            UnivariatePolynomial share = mainPolynomial.evaluateAtX(id);
            mainShares.add(share);

            if (verbose && i < 3) { // 只显示前3个参与者的主份额
                System.out.printf("参与者 P%d (ID=%d) 的主份额: %s\n", i + 1, id, share.toString());
            }
        }

        // 生成工作份额
        this.workingShares = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            BigInteger workingShare = mainShares.get(i).evaluate(BigInteger.ZERO);
            workingShares.add(workingShare);

            if (verbose && i < 3) { // 只显示前3个参与者的工作份额
                System.out.printf("参与者 P%d 的初始工作份额: T%d = %s\n", i + 1, i + 1, workingShare);
            }
        }
        long shareEnd = System.nanoTime();

        long endTime = System.nanoTime();
        stats.addInitTime(endTime - startTime);

        if (verbose) {
            System.out.printf("主份额和工作份额生成时间: %.3f ms\n", (shareEnd - shareStart) / 1e6);
            System.out.println("=== 系统初始化完成 ===");
            System.out.printf("初始化总时间: %.3f ms\n", (endTime - startTime) / 1e6);
        }
    }

    /**
     * 阈值下调协议：将当前阈值降低到新阈值
     * @param newThreshold 新的阈值（必须小于当前阈值）
     */
    public void thresholdDecrease(int newThreshold) {
        if (newThreshold >= currentThreshold) {
            throw new IllegalArgumentException("新阈值必须小于当前阈值");
        }

        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n=== 阈值调整开始 ===");
            System.out.println("当前阈值: " + currentThreshold + " → 新阈值: " + newThreshold);
            System.out.println("参与阈值调整的参与者: P1 - P" + currentThreshold);
        }

        // 步骤1: 计算拉格朗日分量
        List<BigInteger> lagrangeComponents = new ArrayList<>();
        if (verbose) System.out.println("\n步骤1: 计算拉格朗日分量");

        for (int i = 0; i < currentThreshold; i++) {
            BigInteger lagrangeCoeff = computeLagrangeCoefficient(i, currentThreshold);
            BigInteger mainShareValue = mainShares.get(i).evaluate(BigInteger.ZERO);
            BigInteger component = mainShareValue.multiply(lagrangeCoeff).mod(p);
            lagrangeComponents.add(component);

            if (verbose) {
                System.out.printf("P%d: L%d = %s, S%d(0) = %s, c%d = %s\n",
                        i + 1, i + 1, lagrangeCoeff, i + 1, mainShareValue, i + 1, component);
            }
        }

        // 步骤2: 生成重共享多项式
        List<BivariatePolynomial> resharePolynomials = new ArrayList<>();
        if (verbose) System.out.println("\n步骤2: 生成重共享多项式");

        for (int i = 0; i < currentThreshold; i++) {
            BigInteger component = lagrangeComponents.get(i);
            BivariatePolynomial poly = new BivariatePolynomial(newThreshold, p, component, false);
            resharePolynomials.add(poly);

            if (verbose) {
                System.out.printf("P%d 的重共享多项式 h%d(x,y) 常数项 = %s\n",
                        i + 1, i + 1, component);
            }
        }

        // 步骤3: 生成加密共享值并广播
        List<List<BigInteger>> encryptedShares = new ArrayList<>();
        if (verbose) System.out.println("\n步骤3: 生成加密共享值并广播");

        for (int i = 0; i < currentThreshold; i++) {
            List<BigInteger> encryptedRow = new ArrayList<>();
            BivariatePolynomial poly = resharePolynomials.get(i);

            if (verbose) System.out.printf("参与者 P%d 的加密共享值:\n", i + 1);

            for (int j = 0; j < n; j++) {
                BigInteger shareValue = poly.evaluate(participantIDs.get(j), BigInteger.ZERO);
                BigInteger pairingKey = mainPolynomial.evaluate(participantIDs.get(i), participantIDs.get(j));
                BigInteger encrypted = shareValue.add(pairingKey).mod(p);
                encryptedRow.add(encrypted);

                if (verbose) {
                    System.out.printf("  对 P%d: v_%d%d = %s, k_%d%d = %s, C_%d%d = %s\n",
                            j + 1, i + 1, j + 1, shareValue, i + 1, j + 1, pairingKey, i + 1, j + 1, encrypted);
                }
            }
            encryptedShares.add(encryptedRow);
        }

        // 步骤4: 解密并计算新工作份额
        List<BigInteger> newWorkingShares = new ArrayList<>();
        if (verbose) System.out.println("\n步骤4: 解密并计算新工作份额");

        for (int k = 0; k < n; k++) {
            BigInteger sum = BigInteger.ZERO;
            if (verbose) System.out.printf("参与者 P%d 解密过程:\n", k + 1);

            for (int i = 0; i < currentThreshold; i++) {
                BigInteger encrypted = encryptedShares.get(i).get(k);
                BigInteger pairingKey = mainPolynomial.evaluate(participantIDs.get(k), participantIDs.get(i));
                BigInteger decrypted = encrypted.subtract(pairingKey).mod(p);
                sum = sum.add(decrypted).mod(p);

                if (verbose) {
                    System.out.printf("  从 P%d: C_%d%d = %s, k_%d%d = %s, v_%d%d = %s\n",
                            i + 1, i + 1, k + 1, encrypted, k + 1, i + 1, pairingKey, i + 1, k + 1, decrypted);
                }
            }
            newWorkingShares.add(sum);

            if (verbose) {
                System.out.printf("  P%d 的新工作份额 T%d = %s\n", k + 1, k + 1, sum);
            }
        }

        this.workingShares = newWorkingShares;
        this.currentThreshold = newThreshold;

        long endTime = System.nanoTime();
        stats.addThresholdAdjustTime(endTime - startTime);

        if (verbose) {
            System.out.println("=== 阈值调整完成 ===");
            System.out.printf("阈值调整总时间: %.3f ms\n", (endTime - startTime) / 1e6);
        }
    }

    /**
     * 阈值上调协议：将当前阈值提高到新阈值
     * @param newThreshold 新的阈值（必须大于当前阈值）
     */
    public void thresholdIncrease(int newThreshold) {
        if (newThreshold <= currentThreshold) {
            throw new IllegalArgumentException("新阈值必须大于当前阈值");
        }

        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n=== 阈值上调开始 ===");
            System.out.println("当前阈值: " + currentThreshold + " → 新阈值: " + newThreshold);
            System.out.println("扩展阶数 k = " + (newThreshold - currentThreshold));
        }

        // 步骤1: 生成扩展多项式
        BivariatePolynomial extensionPoly = new BivariatePolynomial(newThreshold, p, BigInteger.ZERO, false);

        // 步骤2: 更新主多项式（添加扩展部分）
        this.mainPolynomial = extendBivariatePolynomial(mainPolynomial, extensionPoly, newThreshold);

        // 步骤3: 更新主份额
        for (int i = 0; i < n; i++) {
            BigInteger id = participantIDs.get(i);
            UnivariatePolynomial extensionShare = extensionPoly.evaluateAtX(id);
            UnivariatePolynomial newMainShare = mainShares.get(i).add(extensionShare);
            mainShares.set(i, newMainShare);
        }

        // 步骤4: 更新工作份额
        for (int i = 0; i < n; i++) {
            BigInteger extensionValue = extensionPoly.evaluate(participantIDs.get(i), BigInteger.ZERO);
            BigInteger newWorkingShare = workingShares.get(i).add(extensionValue).mod(p);
            workingShares.set(i, newWorkingShare);
        }

        this.currentThreshold = newThreshold;

        long endTime = System.nanoTime();
        stats.addThresholdIncreaseTime(endTime - startTime);

        if (verbose) {
            System.out.println("=== 阈值上调完成 ===");
            System.out.printf("阈值上调总时间: %.3f ms\n", (endTime - startTime) / 1e6);
        }
    }

    /**
     * 扩展双变量多项式到更高阶数
     * @param original 原始多项式
     * @param extension 扩展多项式
     * @param newDegree 新的阶数
     * @return 扩展后的多项式
     */
    private BivariatePolynomial extendBivariatePolynomial(BivariatePolynomial original,
                                                          BivariatePolynomial extension, int newDegree) {
        BivariatePolynomial newPoly = new BivariatePolynomial(newDegree, p, BigInteger.ZERO, false);

        // 复制原始系数
        for (int i = 0; i < original.degree + 1; i++) {
            for (int j = 0; j < original.degree + 1; j++) {
                newPoly.setCoefficient(i, j, original.coefficients[i][j]);
            }
        }

        // 添加扩展系数
        for (int i = 0; i < extension.degree + 1; i++) {
            for (int j = 0; j < extension.degree + 1; j++) {
                if (i >= original.degree + 1 || j >= original.degree + 1) {
                    BigInteger current = newPoly.coefficients[i][j];
                    newPoly.setCoefficient(i, j, current.add(extension.coefficients[i][j]).mod(p));
                }
            }
        }

        return newPoly;
    }

    /**
     * 工作份额更新：基于上下文信息和轮次更新工作份额
     * @param contextInfo 上下文信息（用于生成随机种子）
     * @param updateRound 更新轮次
     */
    public void workingShareUpdate(String contextInfo, int updateRound) {
        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n=== 工作份额更新开始 ===");
            System.out.println("更新轮次: " + updateRound + ", 上下文信息: " + contextInfo);
        }

        // 步骤1: 生成公共随机种子
        BigInteger randomSeed = generateRandomSeed(contextInfo, updateRound);
        if (verbose) System.out.println("公共随机种子: " + randomSeed);

        // 步骤2: 生成更新多项式
        BivariatePolynomial updatePoly = generateUpdatePolynomial(randomSeed, currentThreshold);
        if (verbose) {
            System.out.println("生成的更新多项式:");
            System.out.println(updatePoly.toString());
        }

        // 步骤3: 更新工作份额
        if (verbose) System.out.println("工作份额更新过程:");
        for (int i = 0; i < n; i++) {
            BigInteger oldShare = workingShares.get(i);
            BigInteger updateValue = updatePoly.evaluate(participantIDs.get(i), BigInteger.ZERO);
            BigInteger newShare = oldShare.add(updateValue).mod(p);
            workingShares.set(i, newShare);

            if (verbose && i < 3) {
                System.out.printf("P%d: T_%d^(old) = %s, Δ(%d,0) = %s, T_%d^(new) = %s\n",
                        i + 1, i + 1, oldShare, i + 1, updateValue, i + 1, newShare);
            }
        }

        long endTime = System.nanoTime();
        stats.addWorkingShareUpdateTime(endTime - startTime);

        if (verbose) {
            System.out.println("=== 工作份额更新完成 ===");
            System.out.printf("工作份额更新总时间: %.3f ms\n", (endTime - startTime) / 1e6);
        }
    }

    /**
     * 主份额更新：基于上下文信息和轮次更新主份额
     * @param contextInfo 上下文信息（用于生成随机种子）
     * @param updateRound 更新轮次
     */
    public void mainShareUpdate(String contextInfo, int updateRound) {
        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n=== 主份额更新开始 ===");
            System.out.println("更新轮次: " + updateRound + ", 上下文信息: " + contextInfo);
        }

        // 步骤1: 生成公共随机种子
        BigInteger randomSeed = generateRandomSeed(contextInfo, updateRound);
        if (verbose) System.out.println("公共随机种子: " + randomSeed);

        // 步骤2: 生成更新多项式
        BivariatePolynomial updatePoly = generateUpdatePolynomial(randomSeed, currentThreshold);
        if (verbose) {
            System.out.println("生成的更新多项式:");
            System.out.println(updatePoly.toString());
        }

        // 步骤3: 更新主份额
        if (verbose) System.out.println("主份额更新过程:");
        for (int i = 0; i < n; i++) {
            UnivariatePolynomial oldMainShare = mainShares.get(i);
            UnivariatePolynomial updatePolyAtID = updatePoly.evaluateAtX(participantIDs.get(i));
            UnivariatePolynomial newMainShare = oldMainShare.add(updatePolyAtID);
            mainShares.set(i, newMainShare);

            if (verbose && i < 2) {
                System.out.printf("P%d 主份额更新:\n", i + 1);
                System.out.printf("  旧主份额: %s\n", oldMainShare.toString());
                System.out.printf("  更新多项式在 ID=%d 的值: %s\n", i + 1, updatePolyAtID.toString());
                System.out.printf("  新主份额: %s\n", newMainShare.toString());
            }
        }

        long endTime = System.nanoTime();
        stats.addMasterShareUpdateTime(endTime - startTime);

        if (verbose) {
            System.out.println("=== 主份额更新完成 ===");
            System.out.printf("主份额更新总时间: %.3f ms\n", (endTime - startTime) / 1e6);
        }
    }

    /**
     * 秘密恢复：使用指定参与者的工作份额恢复秘密
     * @param participantIndices 参与恢复的参与者索引列表
     * @return 恢复的秘密值
     */
    public BigInteger secretRecovery(List<Integer> participantIndices) {
        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n=== 秘密恢复开始 ===");
            System.out.print("参与恢复的参与者: ");
            for (int idx : participantIndices) {
                System.out.print("P" + (idx + 1) + " ");
            }
            System.out.println("\n当前阈值: " + currentThreshold);
        }

        if (participantIndices.size() < currentThreshold) {
            throw new IllegalArgumentException("参与者数量不足，需要至少 " + currentThreshold + " 个参与者");
        }

        BigInteger recoveredSecret = BigInteger.ZERO;

        if (verbose) System.out.println("\n基于工作份额的拉格朗日插值恢复:");

        // 使用工作份额进行恢复
        for (int idx : participantIndices) {
            BigInteger lagrangeCoeff = computeLagrangeCoefficientForRecovery(idx, participantIndices);
            BigInteger term = workingShares.get(idx).multiply(lagrangeCoeff).mod(p);
            recoveredSecret = recoveredSecret.add(term).mod(p);

            if (verbose) {
                System.out.printf("P%d: T_%d = %s, L_%d = %s, 贡献值 = %s\n",
                        idx + 1, idx + 1, workingShares.get(idx), idx + 1, lagrangeCoeff, term);
            }
        }

        long endTime = System.nanoTime();
        stats.addRecoveryTime(endTime - startTime);

        if (verbose) {
            System.out.printf("恢复的秘密: %s\n", recoveredSecret);
            System.out.println("=== 秘密恢复完成 ===");
            System.out.printf("秘密恢复总时间: %.3f ms\n", (endTime - startTime) / 1e6);
        }

        return recoveredSecret;
    }

    /**
     * 计算拉格朗日系数（用于阈值调整）
     * @param index 参与者索引
     * @param threshold 当前阈值
     * @return 拉格朗日系数
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
     * @param index 参与者索引
     * @param indices 所有参与恢复的参与者索引
     * @return 拉格朗日系数
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
     * 生成随机种子：基于上下文信息和轮次生成密码学安全的随机种子
     * @param contextInfo 上下文信息
     * @param round 轮次
     * @return 随机种子
     */
    private BigInteger generateRandomSeed(String contextInfo, int round) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String input = previousSeed.toString() + contextInfo + round;
            byte[] hash = digest.digest(input.getBytes());
            BigInteger newSeed = new BigInteger(1, hash).mod(p);
            previousSeed = newSeed;
            return newSeed;
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * 生成更新多项式：基于随机种子生成对称双变量更新多项式
     * @param seed 随机种子
     * @param threshold 当前阈值
     * @return 更新多项式
     */
    private BivariatePolynomial generateUpdatePolynomial(BigInteger seed, int threshold) {
        try {
            SecureRandom prng = new SecureRandom(seed.toByteArray());
            int coefficientCount = threshold * (threshold + 1) / 2 - 1; // 排除常数项
            int bytesNeeded = coefficientCount * 32; // 每个系数32字节

            byte[] bitStream = new byte[bytesNeeded];
            prng.nextBytes(bitStream); // 生成连续比特流

            // 划分比特流为系数段并转换为有限域元素
            BivariatePolynomial updatePoly = new BivariatePolynomial(threshold, p, BigInteger.ZERO, false);
            int streamIndex = 0;

            for (int i = 0; i < threshold; i++) {
                for (int j = i; j < threshold; j++) {
                    if (i == 0 && j == 0) continue;

                    // 从比特流中提取32字节作为当前系数
                    byte[] coefficientBytes = new byte[32];
                    System.arraycopy(bitStream, streamIndex, coefficientBytes, 0, 32);
                    streamIndex += 32;

                    BigInteger coeff = new BigInteger(1, coefficientBytes).mod(p);
                    updatePoly.setCoefficient(i, j, coeff);
                    if (i != j) {
                        updatePoly.setCoefficient(j, i, coeff);
                    }
                }
            }
            return updatePoly;
        } catch (Exception e) {
            throw new RuntimeException("生成更新多项式失败", e);
        }
    }

    /**
     * 性能统计类：收集和统计各种操作的时间性能数据
     */
    public static class PerformanceStats {
        private List<Long> initTimes = new ArrayList<>();
        private List<Long> thresholdAdjustTimes = new ArrayList<>();
        private List<Long> thresholdIncreaseTimes = new ArrayList<>();  // 新增：阈值上调时间
        private List<Long> workingShareUpdateTimes = new ArrayList<>();
        private List<Long> masterShareUpdateTimes = new ArrayList<>();
        private List<Long> recoveryTimes = new ArrayList<>();
        private List<Long> mixedScenarioTimes = new ArrayList<>();  // 新增：混合场景总耗时

        public void addInitTime(long time) { initTimes.add(time); }
        public void addThresholdAdjustTime(long time) { thresholdAdjustTimes.add(time); }
        public void addThresholdIncreaseTime(long time) { thresholdIncreaseTimes.add(time); }  // 新增
        public void addWorkingShareUpdateTime(long time) { workingShareUpdateTimes.add(time); }
        public void addMasterShareUpdateTime(long time) { masterShareUpdateTimes.add(time); }
        public void addRecoveryTime(long time) { recoveryTimes.add(time); }
        public void addMixedScenarioTime(long time) { mixedScenarioTimes.add(time); }

        // 确保所有列表都有默认值，避免空指针
        public PerformanceStats() {
            // 初始化空列表，确保后续操作不会出现空指针
        }

        /**
         * 打印性能统计结果
         */
        public void printStats() {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("性能统计 (" + initTimes.size() + " 次实验)");
            System.out.println("=".repeat(60));

            System.out.printf("系统初始化平均时间: %.3f ms (标准差: %.3f ms)\n",
                    calculateAverage(initTimes) / 1e6, calculateStdDev(initTimes) / 1e6);
            System.out.printf("阈值下调平均时间: %.3f ms (标准差: %.3f ms)\n",
                    calculateAverage(thresholdAdjustTimes) / 1e6, calculateStdDev(thresholdAdjustTimes) / 1e6);
            System.out.printf("阈值上调平均时间: %.3f ms (标准差: %.3f ms)\n",
                    calculateAverage(thresholdIncreaseTimes) / 1e6, calculateStdDev(thresholdIncreaseTimes) / 1e6);
            System.out.printf("工作份额更新平均时间: %.3f ms (标准差: %.3f ms)\n",
                    calculateAverage(workingShareUpdateTimes) / 1e6, calculateStdDev(workingShareUpdateTimes) / 1e6);
            System.out.printf("主份额更新平均时间: %.3f ms (标准差: %.3f ms)\n",
                    calculateAverage(masterShareUpdateTimes) / 1e6, calculateStdDev(masterShareUpdateTimes) / 1e6);
            System.out.printf("秘密恢复平均时间: %.3f ms (标准差: %.3f ms)\n",
                    calculateAverage(recoveryTimes) / 1e6, calculateStdDev(recoveryTimes) / 1e6);
            System.out.printf("混合场景总平均时间: %.3f ms (标准差: %.3f ms)\n",
                    calculateAverage(mixedScenarioTimes) / 1e6, calculateStdDev(mixedScenarioTimes) / 1e6);

            // 输出详细时间分布
            System.out.println("\n时间分布 (ms):");
            System.out.printf("初始化: %s\n", formatTimeStats(initTimes));
            System.out.printf("阈值下调: %s\n", formatTimeStats(thresholdAdjustTimes));
            System.out.printf("阈值上调: %s\n", formatTimeStats(thresholdIncreaseTimes));
            System.out.printf("工作份额更新: %s\n", formatTimeStats(workingShareUpdateTimes));
            System.out.printf("主份额更新: %s\n", formatTimeStats(masterShareUpdateTimes));
            System.out.printf("秘密恢复: %s\n", formatTimeStats(recoveryTimes));
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
         * @param other 其他统计对象
         */
        public void merge(PerformanceStats other) {
            this.initTimes.addAll(other.initTimes);
            this.thresholdAdjustTimes.addAll(other.thresholdAdjustTimes);
            this.thresholdIncreaseTimes.addAll(other.thresholdIncreaseTimes);
            this.workingShareUpdateTimes.addAll(other.workingShareUpdateTimes);
            this.masterShareUpdateTimes.addAll(other.masterShareUpdateTimes);
            this.recoveryTimes.addAll(other.recoveryTimes);
            this.mixedScenarioTimes.addAll(other.mixedScenarioTimes);
        }
    }

    /**
     * 双变量多项式类：表示对称双变量多项式
     */
    private static class BivariatePolynomial {
        private int degree;
        private BigInteger p;
        private BigInteger[][] coefficients;

        /**
         * 构造函数：创建双变量多项式
         * @param threshold 阈值（多项式阶数为threshold-1）
         * @param p 有限域素数
         * @param constantTerm 常数项（秘密值）
         * @param verbose 是否输出详细日志
         */
        public BivariatePolynomial(int threshold, BigInteger p, BigInteger constantTerm, boolean verbose) {
            this.degree = threshold - 1;
            this.p = p;
            this.coefficients = new BigInteger[threshold][threshold];

            if (verbose) {
                System.out.println("构造 " + degree + " 次对称双变量多项式");
                System.out.println("需要生成 " + (threshold * (threshold + 1) / 2) + " 个系数");
            }

            // 初始化所有系数为0
            for (int i = 0; i < threshold; i++) {
                for (int j = 0; j < threshold; j++) {
                    coefficients[i][j] = BigInteger.ZERO;
                }
            }

            // 设置常数项
            coefficients[0][0] = constantTerm.mod(p);

            // 生成随机系数，保持对称性
            SecureRandom random = new SecureRandom();
            int coefficientCount = 0;
            for (int i = 0; i < threshold; i++) {
                for (int j = i; j < threshold; j++) {
                    if (i == 0 && j == 0) continue;
                    byte[] bytes = new byte[32];
                    random.nextBytes(bytes);
                    BigInteger coeff = new BigInteger(1, bytes).mod(p);
                    coefficients[i][j] = coeff;
                    coefficients[j][i] = coeff; // 对称性
                    coefficientCount++;

                    if (verbose && i <= threshold && j <= threshold) { // 只输出前几个系数
                        System.out.printf("系数 a[%d][%d] = a[%d][%d] = %s\n",
                                i, j, j, i, coeff);
                    }
                }
            }

            if (verbose) {
                System.out.println("多项式构造完成，共生成 " + coefficientCount + " 个随机系数");
                System.out.println("常数项 a[0][0] = " + coefficients[0][0]);
            }
        }

        public void setCoefficient(int i, int j, BigInteger value) {
            coefficients[i][j] = value.mod(p);
        }

        /**
         * 计算多项式在给定点(x,y)的值
         * @param x x坐标
         * @param y y坐标
         * @return 多项式值
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
         * @param x x坐标
         * @return 关于y的单变量多项式
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
         * @param y y坐标
         * @return 多项式值
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
         * @param other 另一个多项式
         * @return 相加后的新多项式
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
     * 阈值测试任务类：实现Callable接口，用于多线程测试
     */
    private static class ThresholdTestTask implements Callable<ThresholdTestResult> {
        private final int threshold;
        private final int numExperiments;
        private final boolean verbose;
        private final String testType;  // 测试类型："basic", "increase", "mixed"

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

            // 打乱实验顺序，减少顺序效应
            List<Integer> experimentOrder = new ArrayList<>();
            for (int i = 0; i < numExperiments; i++) {
                experimentOrder.add(i);
            }
            Collections.shuffle(experimentOrder);

            for (int expIndex = 0; expIndex < numExperiments; expIndex++) {
                int exp = experimentOrder.get(expIndex);
                try {
                    boolean expVerbose = verbose && (exp < 1); // 每个线程只输出第一次实验的详细日志

                    if (expVerbose) {
                        System.out.printf("[%s] 第 %d 次实验 (阈值 t=%d, 测试类型: %s, 详细日志模式)\n",
                                threadName, exp + 1, threshold, testType);
                    } else if (exp % 25 == 0) {
                        System.out.printf("[%s] 进行第 %d 次实验 (阈值 t=%d, 测试类型: %s)...\n",
                                threadName, exp + 1, threshold, testType);
                    }

                    // 创建系统实例
                    DynamicThresholdSecretSharingVersion2App system = new DynamicThresholdSecretSharingVersion2App(
                            NUM_PARTICIPANTS, threshold, expVerbose);

                    // 1. 系统初始化
                    system.systemInitialization(system.secret);

                    // 根据测试类型执行不同的操作序列
                    switch (testType) {
                        case "basic":
                            // 基础测试：下调 + 份额更新
                            if (threshold > 2) {
                                system.thresholdDecrease(threshold - 1);
                            }
                            system.workingShareUpdate("test_update", 1);
                            system.mainShareUpdate("test_update", 1);
                            break;

                        case "increase":
                            // 阈值上调测试 - 分别测试每个扩展阶数
                            if (verbose) {
                                System.out.println("\n=== 阈值上调测试开始 ===");
                                System.out.println("原始阈值: " + threshold);
                            }
                            for (int k : EXTENSION_ORDERS) {
                                int newThreshold = threshold + k;
                                if (newThreshold <= 10) { // 确保不超过最大阈值
                                    if (verbose) {
                                        System.out.println("执行阈值上调: " + threshold + " → " + newThreshold);
                                    }

                                    long increaseStart = System.nanoTime();
                                    system.thresholdIncrease(newThreshold);
                                    long increaseEnd = System.nanoTime();

                                    // 记录每次上调的时间
                                    threadStats.addThresholdIncreaseTime(increaseEnd - increaseStart);

                                    if (verbose) {
                                        System.out.printf("阈值从 %d 上调到 %d 完成，耗时: %.3f ms\n",
                                                threshold, newThreshold, (increaseEnd - increaseStart) / 1e6);
                                    }

                                    // 验证上调后的系统状态
                                    List<Integer> recoveryParticipants = new ArrayList<>();
                                    for (int i = 0; i < system.currentThreshold; i++) {
                                        recoveryParticipants.add(i);
                                    }
                                    BigInteger recoveredAfterIncrease = system.secretRecovery(recoveryParticipants);

                                    if (!recoveredAfterIncrease.equals(system.secret)) {
                                        System.out.printf("警告: 阈值上调后秘密恢复验证失败! 期望: %s, 实际: %s\n",
                                                system.secret, recoveredAfterIncrease);
                                    } else if (verbose) {
                                        System.out.println("✓ 阈值上调后秘密恢复验证成功");
                                    }
                                }
                            }
                            break;

                        case "mixed":
                            // 混合场景测试：上调 -> 工作份额更新 -> 下调 -> 主份额更新
                            if (verbose) {
                                System.out.println("\n=== 混合场景测试开始 ===");
                                System.out.println("初始阈值: " + threshold);
                            }
                            long mixedTotalStart = System.nanoTime();

                            if (threshold < 10) {
                                int originalThreshold = threshold;

                                // 1. 阈值上调
                                if (verbose) System.out.println("步骤1: 阈值上调");
                                long increaseStart = System.nanoTime();
                                system.thresholdIncrease(threshold + 1);
                                long increaseEnd = System.nanoTime();
                                threadStats.addThresholdIncreaseTime(increaseEnd - increaseStart);

                                // 2. 工作份额更新
                                if (verbose) System.out.println("步骤2: 工作份额更新");
                                long workingUpdateStart = System.nanoTime();
                                system.workingShareUpdate("mixed_scenario", 1);
                                long workingUpdateEnd = System.nanoTime();
                                threadStats.addWorkingShareUpdateTime(workingUpdateEnd - workingUpdateStart);

                                // 3. 阈值下调
                                if (verbose) System.out.println("步骤3: 阈值下调");
                                long decreaseStart = System.nanoTime();
                                system.thresholdDecrease(originalThreshold);
                                long decreaseEnd = System.nanoTime();
                                threadStats.addThresholdAdjustTime(decreaseEnd - decreaseStart);

                                // 4. 主份额更新
                                if (verbose) System.out.println("步骤4: 主份额更新");
                                long masterUpdateStart = System.nanoTime();
                                system.mainShareUpdate("mixed_scenario", 1);
                                long masterUpdateEnd = System.nanoTime();
                                threadStats.addMasterShareUpdateTime(masterUpdateEnd - masterUpdateStart);

                                // 验证混合场景后的系统状态
                                List<Integer> recoveryParticipants = new ArrayList<>();
                                for (int i = 0; i < system.currentThreshold; i++) {
                                    recoveryParticipants.add(i);
                                }
                                BigInteger recoveredAfterMixed = system.secretRecovery(recoveryParticipants);

                                if (!recoveredAfterMixed.equals(system.secret)) {
                                    System.out.printf("警告: 混合场景后秘密恢复验证失败! 期望: %s, 实际: %s\n",
                                            system.secret, recoveredAfterMixed);
                                } else if (verbose) {
                                    System.out.println("✓ 混合场景后秘密恢复验证成功");
                                }
                            }

                            long mixedTotalEnd = System.nanoTime();
                            // 记录混合场景总耗时
                            threadStats.addMixedScenarioTime(mixedTotalEnd - mixedTotalStart);

                            if (verbose) {
                                System.out.printf("混合场景测试完成，总耗时: %.3f ms\n",
                                        (mixedTotalEnd - mixedTotalStart) / 1e6);
                            }
                            break;
                    }

                    // 4. 秘密恢复（验证正确性）
                    List<Integer> recoveryParticipants = new ArrayList<>();
                    for (int i = 0; i < system.currentThreshold; i++) {
                        recoveryParticipants.add(i);
                    }
                    BigInteger recovered = system.secretRecovery(recoveryParticipants);

                    // 验证恢复的正确性
                    if (!recovered.equals(system.secret)) {
                        System.out.printf("[%s] 警告: 秘密恢复验证失败! 期望: %s, 实际: %s\n",
                                threadName, system.secret, recovered);
                        failureCount++;
                    } else {
                        successCount++;
                        if (expVerbose) {
                            System.out.printf("[%s] ✓ 秘密恢复验证成功\n", threadName);
                        }
                    }

                    // 收集统计信息
                    threadStats.addInitTime(system.stats.initTimes.get(0));
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
                    if (system.stats.recoveryTimes.size() > 0) {
                        threadStats.addRecoveryTime(system.stats.recoveryTimes.get(0));
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
     * 阈值测试结果类：封装单次测试的结果
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
     * JVM预热方法：执行预热操作以减少JIT编译对性能测试的影响
     */
    private static void performWarmup() {
        System.out.println("执行JVM预热...");
        ExecutorService warmupExecutor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
        List<Future<?>> warmupFutures = new ArrayList<>();

        for (int i = 0; i < WARMUP_COUNT; i++) {
            for (int threshold : THRESHOLDS) {
                warmupFutures.add(warmupExecutor.submit(() -> {
                    try {
                        DynamicThresholdSecretSharingVersion2App warmupSystem =
                                new DynamicThresholdSecretSharingVersion2App(5, 3, false);
                        warmupSystem.systemInitialization(warmupSystem.secret);
                    } catch (Exception e) {
                        // 忽略预热阶段的异常
                    }
                }));
            }
        }

        // 等待所有预热任务完成
        for (Future<?> future : warmupFutures) {
            try {
                future.get();
            } catch (Exception e) {
                // 忽略异常
            }
        }

        warmupExecutor.shutdown();
        System.out.println("JVM预热完成\n");
    }

    /**
     * 主方法：程序入口点，执行多线程性能测试
     */
    public static void main(String[] args) {
        System.out.println("开始动态阈值秘密共享系统性能测试（多线程版本）...");
        System.out.println("参数设置: n=" + NUM_PARTICIPANTS + ", 阈值=" + Arrays.toString(THRESHOLDS));
        System.out.println("实验次数: " + NUM_EXPERIMENTS);
        System.out.println("素数位数: " + PRIME_BIT_LENGTH);
        System.out.println("线程池大小: " + THREAD_POOL_SIZE);
        System.out.println("预热次数: " + WARMUP_COUNT);
        System.out.println("扩展阶数: " + Arrays.toString(EXTENSION_ORDERS));
        System.out.println();

        // JVM预热
        performWarmup();

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
                // 对于阈值上调测试，只测试基础阈值4，但要确保任务被提交
                if (testType.equals("increase")) {
                    if (threshold == 4) {  // 只对阈值4执行上调测试
                        Future<ThresholdTestResult> future = executor.submit(
                                new ThresholdTestTask(threshold, NUM_EXPERIMENTS, true, testType)
                        );
                        futures.add(future);
                    }
                    continue;  // 对其他阈值跳过，但要确保阈值4的任务被提交
                }
                // 对于混合场景测试，只测试合适的阈值范围
                if (testType.equals("mixed")) {
                    if (threshold >= 4 && threshold < 10) {  // 对4-9执行混合场景测试
                        Future<ThresholdTestResult> future = executor.submit(
                                new ThresholdTestTask(threshold, NUM_EXPERIMENTS, true, testType)
                        );
                        futures.add(future);
                    }
                    continue;  // 对其他阈值跳过
                }

                // 基础测试：对所有阈值执行
                if (testType.equals("basic")) {
                    Future<ThresholdTestResult> future = executor.submit(
                            new ThresholdTestTask(threshold, NUM_EXPERIMENTS, true, testType)
                    );
                    futures.add(future);
                }
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
                e.printStackTrace();
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
                if (!testTypeStats.get(testType).containsKey(threshold) ||
                        testTypeStats.get(testType).get(threshold).initTimes.isEmpty()) {
                    continue;
                }

                System.out.println("\n阈值 t=" + threshold + ":");
                System.out.printf("成功率: %d/%d (%.2f%%)\n",
                        successCounts.get(testType).get(threshold),
                        NUM_EXPERIMENTS,
                        (successCounts.get(testType).get(threshold) * 100.0 / NUM_EXPERIMENTS));
                testTypeStats.get(testType).get(threshold).printStats();

                // 输出多项式复杂度信息
                int coefficientCount = threshold * (threshold + 1) / 2;
                System.out.printf("多项式系数数量: %d (复杂度: O(t²))\n", coefficientCount);
            }
        }

        // 生成图表数据摘要
        //generateChartSummary(testTypeStats.get("basic"));
        // 生成图表数据摘要 - 合并所有测试类型的数据
        generateChartSummary(mergeAllTestData(testTypeStats));

        System.out.println("\n所有测试完成!");
    }

    /**
     * 合并所有测试类型的数据
     */
    private static Map<Integer, PerformanceStats> mergeAllTestData(Map<String, Map<Integer, PerformanceStats>> testTypeStats) {
        Map<Integer, PerformanceStats> mergedStats = new TreeMap<>();

        // 初始化所有阈值的统计对象
        for (int threshold : THRESHOLDS) {
            mergedStats.put(threshold, new PerformanceStats());
        }

        // 合并所有测试类型的数据
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
     * 生成图表数据摘要：整理性能数据用于图表生成
     * @param statsMap 性能统计映射
     */
    private static void generateChartSummary(Map<Integer, PerformanceStats> statsMap) {
        System.out.println("\n" + "=".repeat(120));
        System.out.println("图表数据摘要 (包含阈值上调和混合场景)");
        System.out.println("=".repeat(120));

        Map<Integer, Map<String, Double>> chartData = new TreeMap<>();

        // 更新表头，增加阈值上调时间列
        System.out.println("\n阈值(t) | 系统初始化(ms) | 阈值下调(ms) | 阈值上调(ms) | 工作份额更新(ms) | 主份额更新(ms) | 秘密恢复(ms) | 混合场景(ms)");
        System.out.println("--------|---------------|-------------|-------------|-----------------|---------------|-------------|-------------");

        for (int threshold : THRESHOLDS) {
            if (!statsMap.containsKey(threshold)) continue;

            Map<String, Double> tData = new HashMap<>();
            PerformanceStats stats = statsMap.get(threshold);

            double initTime = stats.calculateAverage(stats.initTimes) / 1e6;
            double thresholdTime = stats.thresholdAdjustTimes.isEmpty() ? 0 : stats.calculateAverage(stats.thresholdAdjustTimes) / 1e6;
            double thresholdIncreaseTime = stats.thresholdIncreaseTimes.isEmpty() ? 0 : stats.calculateAverage(stats.thresholdIncreaseTimes) / 1e6;
            double workingUpdateTime = stats.workingShareUpdateTimes.isEmpty() ? 0 : stats.calculateAverage(stats.workingShareUpdateTimes) / 1e6;
            double masterUpdateTime = stats.masterShareUpdateTimes.isEmpty() ? 0 : stats.calculateAverage(stats.masterShareUpdateTimes) / 1e6;
            double recoveryTime = stats.recoveryTimes.isEmpty() ? 0 : stats.calculateAverage(stats.recoveryTimes) / 1e6;
            double mixedScenarioTime = stats.mixedScenarioTimes.isEmpty() ? 0 : stats.calculateAverage(stats.mixedScenarioTimes) / 1e6;

            tData.put("系统初始化(ms)", initTime);
            tData.put("阈值下调(ms)", thresholdTime);
            tData.put("阈值上调(ms)", thresholdIncreaseTime);
            tData.put("工作份额更新(ms)", workingUpdateTime);
            tData.put("主份额更新(ms)", masterUpdateTime);
            tData.put("秘密恢复(ms)", recoveryTime);
            tData.put("混合场景(ms)", mixedScenarioTime);
            chartData.put(threshold, tData);

            System.out.printf("   %d    |     %7.3f   |   %7.3f   |   %7.3f   |      %7.3f    |     %7.3f   |   %7.3f   |   %7.3f\n",
                    threshold, initTime, thresholdTime, thresholdIncreaseTime,
                    workingUpdateTime, masterUpdateTime, recoveryTime, mixedScenarioTime);
        }

        System.out.println("\n图表说明:");
        System.out.println("- 横轴 (X-axis): 阈值 t (Threshold t)，标度为 " + Arrays.toString(THRESHOLDS));
        System.out.println("- 纵轴 (Y-axis): 执行时间 (Execution Time / ms)");
        System.out.println("- 图例 (Legend): 包含六条曲线，分别代表:");
        System.out.println("  - 系统初始化 (System Initialization)");
        System.out.println("  - 阈值下调 (Threshold Decreasing, t'=t-1)");
        System.out.println("- 阈值上调测试: 原始阈值 t=4，扩展阶数 k=1,2,3（新阈值 t'=5,6,7）");
        System.out.println("  - 工作份额更新 (Working Share Update)");
        System.out.println("  - 主份额更新 (Master Share Update)");
        System.out.println("  - 混合场景测试: t=4 上调至 t'=5 + 工作份额更新 → t=5 下调至 t'=4 + 主份额更新");
        System.out.println("  - 秘密恢复 (Secret Recovery)");

        SwingUtilities.invokeLater(() -> {
            generatePerformanceChart(chartData);
        });
    }

    /**
     * 绘制性能曲线图
     * @param chartData 图表数据
     */
    public static void generatePerformanceChart(Map<Integer, Map<String, Double>> chartData) {
        // 创建并显示图表
        JFrame frame = new JFrame("核心操作执行时间随阈值变化趋势");
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        PerformanceChart chart = new PerformanceChart();
        chart.setPerformanceData(chartData);
        frame.add(chart);

        frame.pack();
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);

        chart.createAndSaveChart(chartData, "PerformanceChart.png");
    }
}