import javax.swing.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;


/**
 * 动态阈值秘密共享系统版本4应用程序 - 严格按照文档方案优化
 * 实现4.1-4.6节的所有协议和验证
 */
public class DynamicThresholdSecretSharingVersion4App {
    // ============================ 实验参数配置 ============================
    private static final int NUM_PARTICIPANTS = 20;                    // 参与者数量n = 15
    private static final int[] THRESHOLDS = {5,7,9,11,13};             // 测试的阈值范围t = 5, 7, 9, 11, 13
    private static final int NUM_EXPERIMENTS = 1000;                     // 每个阈值的实验次数（减少以便快速测试）
    private static final int PRIME_BIT_LENGTH = 256;                   // 素数位长度

    // 预定义的256位大素数
    private static final BigInteger FIXED_256BIT_PRIME = new BigInteger(
            "115792089237316195423570985008687907853269984665640564039457584007908834671663");

    // 线程池配置
    private static final int THREAD_POOL_SIZE = THRESHOLDS.length;
    private static final int WARMUP_COUNT = 1;                         // 预热次数

    // ============================ 系统状态变量 ============================
    private BigInteger p;                          // 256位大素数
    private int n;                                // 参与者数量
    private int currentThreshold;                 // 当前工作份额的阈值
    private int currentMainThreshold;             // 当前主份额的阈值
    public BigInteger secret;                     // 秘密值
    private List<BigInteger> participantIDs;      // 参与者ID列表
    private BigInteger previousSeed;              // 初始随机数种子

    // ============================ 系统核心组件 ============================
    private BivariatePolynomial mainPolynomial;   // 主多项式
    private List<UnivariatePolynomial> mainShares; // 主份额
    private List<BigInteger> workingShares;       // 工作份额

    // ============================ 性能统计和输出控制 ============================
    private PerformanceStats stats;
    private boolean verbose;                      // 控制详细日志输出

    /**
     * 构造函数：初始化动态阈值秘密共享系统
     * 对应文档4.1节系统模型
     */
    public DynamicThresholdSecretSharingVersion4App(int n, int initialThreshold, boolean verbose) {
        this.n = n;
        this.currentThreshold = initialThreshold;
        this.currentMainThreshold = initialThreshold;
        this.p = FIXED_256BIT_PRIME;
        this.participantIDs = generateParticipantIDs(n);
        this.stats = new PerformanceStats();
        this.verbose = verbose;
        // 使用固定的秘密值和初始种子，确保实验可重复性
        this.secret = new BigInteger("73138218979700741375608676119062004991785096625092157987592068860966427730354").mod(p);
        this.previousSeed = new BigInteger("10101010");

        if (verbose) {
            System.out.println("✓ 系统初始化完成 - 参与者数量: " + n + ", 初始阈值: " + initialThreshold);
            System.out.println("  有限域 GF(p), p = " + p.toString().substring(0, 20) + "...");
            System.out.println("  初始秘密 s = " + secret);
        }
    }

    /**
     * 生成参与者ID列表
     * 对应文档4.1节参与者身份标识
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
     * 对应文档4.2节系统初始化和4.3节双重份额生成与分发
     */
    public void systemInitialization(BigInteger secret) {
        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("4.2 系统初始化开始");
            System.out.println("=".repeat(60));
            System.out.println("秘密值 s = " + secret);
            System.out.println("有限域 GF(p), p = " + p.toString().substring(0, 20) + "...");
            System.out.println("参与者数量 n = " + n);
            System.out.println("初始阈值 t = " + currentThreshold);
            System.out.println("将生成 " + (currentThreshold * (currentThreshold + 1) / 2) + " 个独立系数");
        }

        this.secret = secret;

        // 生成对称双变量多项式 - 对应文档4.2节公式
        if (verbose) System.out.println("\n步骤1: 生成对称双变量多项式 f(x,y)");
        long polyStart = System.nanoTime();
        this.mainPolynomial = new BivariatePolynomial(currentThreshold, p, secret, verbose);
        long polyEnd = System.nanoTime();

        if (verbose) {
            System.out.println("✓ 双变量多项式生成完成");
            System.out.printf("  多项式生成时间: %.3f ms\n", (polyEnd - polyStart) / 1e6);
        }

        // 生成主份额 - 对应文档4.3.1节主份额生成与分发
        if (verbose) System.out.println("\n步骤2: 生成主份额 S_i(y) = f(ID_i, y)");
        long shareStart = System.nanoTime();
        this.mainShares = new ArrayList<>();
        for (int i = 0; i < participantIDs.size(); i++) {
            BigInteger id = participantIDs.get(i);
            UnivariatePolynomial share = mainPolynomial.evaluateAtX(id);
            mainShares.add(share);
            if (verbose) { // 只显示前3个参与者的主份额
                System.out.println("  参与者 P" + (i+1) + " 主份额: " + share.toString().substring(0, 50) + "...");
            }
        }

        // 生成工作份额 - 对应文档4.3.2节工作份额设置
        if (verbose) System.out.println("\n步骤3: 生成工作份额 T_i = S_i(0) = f(ID_i, 0)");
        this.workingShares = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            BigInteger workingShare = mainShares.get(i).evaluate(BigInteger.ZERO);
            workingShares.add(workingShare);
            if (verbose) { // 只显示前3个参与者的工作份额
                System.out.println("  参与者 P" + (i+1) + " 工作份额: " + workingShare);
            }
        }
        long shareEnd = System.nanoTime();

        long endTime = System.nanoTime();
        stats.addInitTime(endTime - startTime);

        if (verbose) {
            System.out.println("\n✓ 系统初始化完成");
            System.out.printf("初始化总时间: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }
    }

    /**
     * 安全阈值下调协议：将当前阈值降低到新阈值
     * 对应文档4.4.2节安全阈值下调协议
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

        // 步骤1: 本地计算拉格朗日分量 - 对应文档步骤一
        if (verbose) System.out.println("\n步骤1: 本地计算拉格朗日分量 c_i = S_i(0) × L_i");
        List<BigInteger> lagrangeComponents = new ArrayList<>();
        for (int i = 0; i < currentThreshold; i++) {
            BigInteger lagrangeCoeff = computeLagrangeCoefficient(i, currentThreshold);
            BigInteger mainShareValue = mainShares.get(i).evaluate(BigInteger.ZERO);
            BigInteger component = mainShareValue.multiply(lagrangeCoeff).mod(p);
            lagrangeComponents.add(component);
            if (verbose) {
                System.out.println("  参与者 P" + (i+1) + " 拉格朗日分量: " + component);
            }
        }

        // 步骤2: 本地生成重共享多项式 - 对应文档步骤二
        if (verbose) System.out.println("\n步骤2: 本地生成重共享多项式 h_i(x,y)");
        List<BivariatePolynomial> resharePolynomials = new ArrayList<>();
        for (int i = 0; i < currentThreshold; i++) {
            BigInteger component = lagrangeComponents.get(i);
            BivariatePolynomial poly = new BivariatePolynomial(newThreshold, p, component, false);
            resharePolynomials.add(poly);
            if (verbose) {
                System.out.println("  参与者 P" + (i+1) + " 重共享多项式: h_" + (i+1) + "(x,y)");
            }
        }

        // 步骤3: 本地生成加密共享值并广播通信 - 对应文档步骤三
        if (verbose) System.out.println("\n步骤3: 生成加密共享值并广播 C_ik = v_ik + k_ik");
        List<List<BigInteger>> encryptedShares = new ArrayList<>();
        for (int i = 0; i < currentThreshold; i++) {
            List<BigInteger> encryptedRow = new ArrayList<>();
            BivariatePolynomial poly = resharePolynomials.get(i);

            for (int j = 0; j < n; j++) {
                BigInteger shareValue = poly.evaluate(participantIDs.get(j), BigInteger.ZERO);
                BigInteger pairingKey = mainPolynomial.evaluate(participantIDs.get(i), participantIDs.get(j));
                BigInteger encrypted = shareValue.add(pairingKey).mod(p);
                encryptedRow.add(encrypted);
            }
            encryptedShares.add(encryptedRow);
            if (verbose) {
                System.out.println("  参与者 P" + (i+1) + " 加密共享值生成完成");
            }
        }

        // 步骤4: 并行解密与计算工作份额 - 对应文档步骤四
        if (verbose) System.out.println("\n步骤4: 并行解密并计算新工作份额");
        List<BigInteger> newWorkingShares = new ArrayList<>();
        for (int k = 0; k < n; k++) {
            BigInteger sum = BigInteger.ZERO;
            for (int i = 0; i < currentThreshold; i++) {
                BigInteger encrypted = encryptedShares.get(i).get(k);
                BigInteger pairingKey = mainPolynomial.evaluate(participantIDs.get(k), participantIDs.get(i));
                BigInteger decrypted = encrypted.subtract(pairingKey).mod(p);
                sum = sum.add(decrypted).mod(p);
            }
            newWorkingShares.add(sum);
            if (verbose) {
                System.out.println("  参与者 P" + (k+1) + " 新工作份额: " + sum);
            }
        }

        this.workingShares = newWorkingShares;
        this.currentThreshold = newThreshold;

        long endTime = System.nanoTime();
        stats.addThresholdAdjustTime(endTime - startTime);

        if (verbose) {
            System.out.println("\n✓ 安全阈值下调完成");
            System.out.printf("阈值下调总时间: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }
    }

    /**
     * 安全阈值上调协议：将当前阈值提高到新阈值
     * 对应文档4.4.1节安全阈值上调协议
     */
    public void thresholdIncrease(int newThreshold) {
        if (newThreshold <= currentThreshold) {
            throw new IllegalArgumentException("新阈值必须大于当前阈值");
        }

        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("4.4.1 安全阈值上调协议开始");
            System.out.println("=".repeat(60));
            System.out.println("当前阈值: " + currentThreshold + " → 新阈值: " + newThreshold);
            System.out.println("扩展阶数 k = " + (newThreshold - currentThreshold));
        }

        // 步骤1: 生成扩展多项式 - 对应文档核心设计
        if (verbose) System.out.println("\n步骤1: 生成扩展多项式");
        BivariatePolynomial extensionPoly = new BivariatePolynomial(newThreshold, p, BigInteger.ZERO, false);

        // 步骤2: 更新主多项式（添加扩展部分）
        if (verbose) System.out.println("步骤2: 更新主多项式");
        this.mainPolynomial = extendBivariatePolynomial(mainPolynomial, extensionPoly, newThreshold);

        // 步骤3: 更新主份额 - 对应文档多项式扩展
        if (verbose) System.out.println("步骤3: 更新主份额 S_i(y) = S_i(y) + Δ(ID_i, y)");
        for (int i = 0; i < n; i++) {
            BigInteger id = participantIDs.get(i);
            UnivariatePolynomial extensionShare = extensionPoly.evaluateAtX(id);
            UnivariatePolynomial newMainShare = mainShares.get(i).add(extensionShare);
            mainShares.set(i, newMainShare);
        }

        // 步骤4: 更新工作份额
        if (verbose) System.out.println("步骤4: 更新工作份额 T_i = T_i + Δ(ID_i, 0)");
        for (int i = 0; i < n; i++) {
            BigInteger extensionValue = extensionPoly.evaluate(participantIDs.get(i), BigInteger.ZERO);
            BigInteger newWorkingShare = workingShares.get(i).add(extensionValue).mod(p);
            workingShares.set(i, newWorkingShare);
            if (verbose) {
                System.out.println("  参与者 P" + (i+1) + " 新工作份额: " + newWorkingShare);
            }
        }

        this.currentThreshold = newThreshold;
        this.currentMainThreshold = newThreshold;

        long endTime = System.nanoTime();
        stats.addThresholdIncreaseTime(endTime - startTime);

        if (verbose) {
            System.out.println("\n✓ 安全阈值上调完成");
            System.out.printf("阈值上调总时间: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }
    }

    /**
     * 扩展双变量多项式到更高阶数
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
     * 工作份额更新协议
     * 对应文档4.5.1节工作份额更新协议
     */
    public void workingShareUpdate(String contextInfo, int updateRound, int threshold) {
        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("4.5.1 工作份额更新协议开始");
            System.out.println("=".repeat(60));
            System.out.println("更新轮次: " + updateRound + ", 上下文信息: " + contextInfo);
            System.out.println("当前阈值: " + threshold);
        }

        // 步骤1: 生成公共随机种子 - 对应文档步骤一
        if (verbose) System.out.println("\n步骤1: 生成公共随机种子 r_k = H(r_{k-1} || info || k)");
        BigInteger randomSeed = generateRandomSeed(contextInfo, updateRound);
        if (verbose) System.out.println("  随机种子: " + randomSeed.toString().substring(0, 20) + "...");

        // 步骤2: 生成更新多项式 - 对应文档步骤二
        if (verbose) System.out.println("步骤2: 生成更新多项式 Δ_k(x,y) = PRG(r_k)");
        BivariatePolynomial updatePoly = generateUpdatePolynomial(randomSeed, threshold);
        if (verbose) System.out.println("  更新多项式生成完成，常数项为0");

        // 步骤3: 更新本地工作份额 - 对应文档步骤三
        if (verbose) System.out.println("步骤3: 更新本地工作份额 T_i^(k) = T_i^(k-1) + Δ_k(ID_i, 0)");
        for (int i = 0; i < n; i++) {
            BigInteger oldShare = workingShares.get(i);
            BigInteger updateValue = updatePoly.evaluate(participantIDs.get(i), BigInteger.ZERO);
            BigInteger newShare = oldShare.add(updateValue).mod(p);
            workingShares.set(i, newShare);
            if (verbose) {
                System.out.println("  参与者 P" + (i+1) + ": " + oldShare + " → " + newShare);
            }
        }

        long endTime = System.nanoTime();
        stats.addWorkingShareUpdateTime(endTime - startTime);

        if (verbose) {
            System.out.println("\n✓ 工作份额更新完成");
            System.out.printf("工作份额更新总时间: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }
    }

    /**
     * 主份额更新协议
     * 对应文档4.5.2节主份额更新协议
     */
    public void mainShareUpdate(String contextInfo, int updateRound, int threshold) {
        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("4.5.2 主份额更新协议开始");
            System.out.println("=".repeat(60));
            System.out.println("更新轮次: " + updateRound + ", 上下文信息: " + contextInfo);
            System.out.println("当前阈值: " + threshold);
        }

        // 步骤1: 生成公共随机种子 - 对应文档步骤一
        if (verbose) System.out.println("\n步骤1: 生成公共随机种子 r_k = H(r_{k-1} || info || k)");
        BigInteger randomSeed = generateRandomSeed(contextInfo, updateRound);
        if (verbose) System.out.println("  随机种子: " + randomSeed.toString().substring(0, 20) + "...");

        // 步骤2: 生成更新多项式 - 对应文档步骤二
        if (verbose) System.out.println("步骤2: 生成更新多项式 Δ_k(x,y) = PRG(r_k)");
        BivariatePolynomial updatePoly = generateUpdatePolynomial(randomSeed, threshold);
        if (verbose) System.out.println("  更新多项式生成完成，常数项为0");

        // 步骤3: 更新本地主份额 - 对应文档步骤三
        if (verbose) System.out.println("步骤3: 更新本地主份额 S_i^(k)(y) = S_i^(k-1)(y) + Δ_k(ID_i, y)");
        for (int i = 0; i < n; i++) {
            UnivariatePolynomial oldMainShare = mainShares.get(i);
            UnivariatePolynomial updatePolyAtID = updatePoly.evaluateAtX(participantIDs.get(i));
            UnivariatePolynomial newMainShare = oldMainShare.add(updatePolyAtID);
            mainShares.set(i, newMainShare);
            if (verbose) {
                System.out.println("  参与者 P" + (i+1) + " 主份额更新完成");
            }
        }

        long endTime = System.nanoTime();
        stats.addMasterShareUpdateTime(endTime - startTime);

        if (verbose) {
            System.out.println("\n✓ 主份额更新完成");
            System.out.printf("主份额更新总时间: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }
    }

    /**
     * 基于工作份额的秘密恢复（优化版）
     * 对应文档4.6.1节基于工作份额的秘密恢复
     */
    public BigInteger secretRecoveryFromWorkingShares(List<Integer> participantIndices) {
        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("4.6.1 基于工作份额的秘密恢复开始");
            System.out.println("=".repeat(60));
            System.out.print("参与恢复的参与者: ");
            for (int idx : participantIndices) {
                System.out.print("P" + (idx + 1) + " ");
            }
            System.out.println("\n当前阈值: " + currentThreshold);
            System.out.println("参与者数量: " + participantIndices.size());
        }

        if (participantIndices.size() < currentThreshold) {
            throw new IllegalArgumentException("参与者数量不足，需要至少 " + currentThreshold + " 个参与者");
        }

        // 步骤1: 预计算配对密钥
        if (verbose) System.out.println("\n步骤1: 预计算配对密钥");
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

                if (verbose && (i == 0 && j == 1)) {
                    System.out.println("  配对密钥 k_" + (idx_i+1) + (idx_j+1) + " = " + pairingKey);
                }
            }
        }

        // 步骤2: 计算拉格朗日分量（使用工作份额）
        if (verbose) System.out.println("\n步骤2: 计算拉格朗日分量 c_i = T_i × L_i");
        List<BigInteger> lagrangeComponents = new ArrayList<>();
        for (int i = 0; i < participantIndices.size(); i++) {
            int idx = participantIndices.get(i);
            BigInteger lagrangeCoeff = computeLagrangeCoefficientForRecovery(idx, participantIndices);
            BigInteger workingShare = workingShares.get(idx); // T_i
            BigInteger component = workingShare.multiply(lagrangeCoeff).mod(p);
            lagrangeComponents.add(component);
            if (verbose && i < 3) {
                System.out.println("  参与者 P" + (idx+1) + " 拉格朗日分量: " + component);
            }
        }

        // 步骤3: 生成发布值（包含配对密钥计算）
        if (verbose) System.out.println("\n步骤3: 生成发布值 v_i = c_i + Σk_il (ID_l < ID_i) - Σk_li (ID_l > ID_i)");
        List<BigInteger> publishedValues = new ArrayList<>();
        for (int i = 0; i < participantIndices.size(); i++) {
            int idx_i = participantIndices.get(i);
            BigInteger component = lagrangeComponents.get(i);
            BigInteger publishedValue = component;

            // 配对密钥计算
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
            if (verbose && i < 3) {
                System.out.println("  参与者 P" + (idx_i+1) + " 发布值: " + publishedValue);
            }
        }

        // 步骤4: 秘密恢复
        if (verbose) System.out.println("\n步骤4: 秘密恢复 s = Σv_i");
        BigInteger recoveredSecret = BigInteger.ZERO;
        for (BigInteger value : publishedValues) {
            recoveredSecret = recoveredSecret.add(value).mod(p);
        }

        long endTime = System.nanoTime();
        stats.addWorkingSharesRecoveryTime(endTime - startTime);

        if (verbose) {
            System.out.println("\n✓ 基于工作份额的秘密恢复完成");
            System.out.printf("恢复的秘密: %s\n", recoveredSecret);
            System.out.printf("原始的秘密: %s\n", secret);
            System.out.println("恢复结果: " + (recoveredSecret.equals(secret) ? "✓ 成功" : "✗ 失败"));
            System.out.printf("恢复时间: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }

        return recoveredSecret;
    }

    /**
     * 基于主份额的秘密恢复（修正版）
     * 对应文档4.6.1节基于主份额的秘密恢复
     * 应该包含配对密钥计算，与工作份额恢复类似
     */
    public BigInteger secretRecoveryFromMainShares(List<Integer> participantIndices) {
        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("4.6.1 基于主份额的秘密恢复开始");
            System.out.println("=".repeat(60));
            System.out.print("参与恢复的参与者: ");
            for (int idx : participantIndices) {
                System.out.print("P" + (idx + 1) + " ");
            }
            System.out.println("\n当前阈值: " + currentMainThreshold);
            System.out.println("参与者数量: " + participantIndices.size());
        }

        if (participantIndices.size() < currentMainThreshold) {
            throw new IllegalArgumentException("参与者数量不足，需要至少 " + currentMainThreshold + " 个参与者");
        }

        // 步骤1: 预计算配对密钥（与工作份额恢复相同）
        if (verbose) System.out.println("\n步骤1: 预计算配对密钥");
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

                if (verbose && (i == 0 && j == 1)) {
                    System.out.println("  配对密钥 k_" + (idx_i+1) + (idx_j+1) + " = " + pairingKey);
                }
            }
        }

        // 步骤2: 计算拉格朗日分量（使用主份额值）
        if (verbose) System.out.println("\n步骤2: 计算拉格朗日分量 c_i = S_i(0) × L_i");
        List<BigInteger> lagrangeComponents = new ArrayList<>();
        for (int i = 0; i < participantIndices.size(); i++) {
            int idx = participantIndices.get(i);
            BigInteger lagrangeCoeff = computeLagrangeCoefficientForRecovery(idx, participantIndices);
            BigInteger mainShareValue = mainShares.get(idx).evaluate(BigInteger.ZERO); // S_i(0)
            BigInteger component = mainShareValue.multiply(lagrangeCoeff).mod(p);
            lagrangeComponents.add(component);
            if (verbose && i < 3) {
                System.out.println("  参与者 P" + (idx+1) + " 拉格朗日分量: " + component);
            }
        }

        // 步骤3: 生成发布值（包含配对密钥计算）
        if (verbose) System.out.println("\n步骤3: 生成发布值 v_i = c_i + Σk_il (ID_l < ID_i) - Σk_li (ID_l > ID_i)");
        List<BigInteger> publishedValues = new ArrayList<>();
        for (int i = 0; i < participantIndices.size(); i++) {
            int idx_i = participantIndices.get(i);
            BigInteger component = lagrangeComponents.get(i);
            BigInteger publishedValue = component;

            // 配对密钥计算（与工作份额恢复相同）
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
            if (verbose && i < 3) {
                System.out.println("  参与者 P" + (idx_i+1) + " 发布值: " + publishedValue);
            }
        }

        // 步骤4: 秘密恢复
        if (verbose) System.out.println("\n步骤4: 秘密恢复 s = Σv_i");
        BigInteger recoveredSecret = BigInteger.ZERO;
        for (BigInteger value : publishedValues) {
            recoveredSecret = recoveredSecret.add(value).mod(p);
        }

        long endTime = System.nanoTime();
        stats.addMainSharesRecoveryTime(endTime - startTime);

        if (verbose) {
            System.out.println("\n✓ 基于主份额的秘密恢复完成");
            System.out.printf("恢复的秘密: %s\n", recoveredSecret);
            System.out.printf("原始的秘密: %s\n", secret);
            System.out.println("恢复结果: " + (recoveredSecret.equals(secret) ? "✓ 成功" : "✗ 失败"));
            System.out.printf("恢复时间: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }

        return recoveredSecret;
    }

    /**
     * 统一的拉格朗日插值实现
     */
    private BigInteger performLagrangeInterpolation(List<Integer> indices, List<BigInteger> shares) {
        BigInteger result = BigInteger.ZERO;

        for (int i = 0; i < indices.size(); i++) {
            int idx = indices.get(i);
            BigInteger lagrangeCoeff = computeLagrangeCoefficientForRecovery(idx, indices);
            BigInteger term = shares.get(i).multiply(lagrangeCoeff).mod(p);
            result = result.add(term).mod(p);
        }

        return result;
    }

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
     * 生成随机种子：基于上下文信息和轮次生成密码学安全的随机种子
     * 对应文档4.5.1节步骤一
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
     * 生成更新多项式：基于随机种子生成对称双变量更新多项式
     * 对应文档4.5.1节步骤二
     */
    private BivariatePolynomial generateUpdatePolynomial(BigInteger seed, int threshold) {
        try {
            // 使用 Bouncy Castle 的安全随机数生成器
            SecureRandom prng = BCCryptoUtils.createSecureRandom(seed.toByteArray());

            if (verbose) {
                System.out.println("  使用 " + prng.getClass().getSimpleName() + " 生成更新多项式");
            }

            // 生成符合文档要求的更新多项式
            BivariatePolynomial updatePoly = new BivariatePolynomial(threshold, p, BigInteger.ZERO, false);

            // 显式设置常数项为0
            updatePoly.setCoefficient(0, 0, BigInteger.ZERO);

            // 生成对称系数，使用 Bouncy Castle 的安全随机数
            int coefficientCount = 0;
            for (int i = 0; i < threshold; i++) {
                for (int j = i; j < threshold; j++) {
                    if (i == 0 && j == 0) continue; // 常数项已设为0

                    // 使用 Bouncy Castle 的安全随机数生成
                    BigInteger coeff = BCCryptoUtils.generateSecureRandomBigInteger(p, prng);

                    updatePoly.setCoefficient(i, j, coeff);
                    if (i != j) {
                        updatePoly.setCoefficient(j, i, coeff);
                    }
                    coefficientCount++;
                }
            }

            if (verbose) {
                System.out.println("  生成 " + coefficientCount + " 个对称系数");
            }

            return updatePoly;
        } catch (Exception e) {
            throw new RuntimeException("生成更新多项式失败: " + e.getMessage(), e);
        }
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
        private BigInteger[][] coefficients;

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

                    // 使用 Bouncy Castle 的安全随机数生成
                    BigInteger coeff = BCCryptoUtils.generateSecureRandomBigInteger(p, secureRandom);

                    coefficients[i][j] = coeff;
                    if (i != j) {
                        coefficients[j][i] = coeff; // 严格对称性
                    }
                    coefficientCount++;

                    if (verbose) { // 只显示前5个系数避免输出过多
                        System.out.println("  系数 a_" + i + j + " = a_" + j + i + " = " + coeff);
                    }
                }
            }

            if (verbose) {
                System.out.println("  共生成 " + coefficientCount + " 个随机系数");
                System.out.println("  使用的随机数生成器: " + secureRandom.getClass().getSimpleName());
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
                    DynamicThresholdSecretSharingVersion4App system = new DynamicThresholdSecretSharingVersion4App(
                            NUM_PARTICIPANTS, threshold, expVerbose);

                    // 1. 系统初始化
                    system.systemInitialization(system.secret);

                    // 根据测试类型执行不同的操作序列
                    switch (testType) {
                        case "basic":
                            // 基础测试：下调 + 份额更新 + 两种恢复方式验证
                            if (threshold > 2) {
                                system.thresholdDecrease(threshold - 1);
                            }
                            system.workingShareUpdate("test_update", 1, system.currentThreshold);
                            system.mainShareUpdate("test_update", 1, system.currentMainThreshold);
                            break;

                        case "increase":
                            // 阈值上调测试
                            if (expVerbose) {
                                System.out.println("\n=== 阈值上调测试开始 ===");
                            }
                            for (int k = 1; k <= 5; k++) {
                                int newThreshold = threshold + k;
                                if (newThreshold <= system.NUM_PARTICIPANTS) {
                                    system.thresholdIncrease(newThreshold);
                                }
                            }
                            break;

                        case "mixed":
                            // 混合场景测试：上调 -> 工作份额更新 -> 下调 -> 主份额更新
                            if (expVerbose) {
                                System.out.println("\n=== 混合场景测试开始 ===");
                            }
                            long mixedTotalStart = System.nanoTime();

                            if (threshold <= THRESHOLDS[THRESHOLDS.length-1]) {
                                int originalThreshold = threshold;

                                // 1. 阈值上调
                                int newThreshold = threshold + 1;
                                system.thresholdIncrease(newThreshold);

                                // 2. 工作份额更新
                                system.workingShareUpdate("mixed_scenario", 1, system.currentThreshold);

                                // 3. 阈值下调
                                system.thresholdDecrease(originalThreshold);

                                // 4. 主份额更新
                                system.mainShareUpdate("mixed_scenario", 1, system.currentMainThreshold);
                            }

                            long mixedTotalEnd = System.nanoTime();
                            threadStats.addMixedScenarioTime(mixedTotalEnd - mixedTotalStart);
                            break;
                    }

                    // 秘密恢复验证
                    List<Integer> recoveryParticipants = new ArrayList<>();
                    for (int i = 0; i < system.currentThreshold; i++) {
                        recoveryParticipants.add(i);
                    }

                    List<Integer> recoveryMainParticipants = new ArrayList<>();
                    for (int i = 0; i < system.currentMainThreshold; i++) {
                        recoveryMainParticipants.add(i);
                    }

                    BigInteger recoveredFromWorking = system.secretRecoveryFromWorkingShares(recoveryParticipants);
                    BigInteger recoveredFromMain = system.secretRecoveryFromMainShares(recoveryMainParticipants);

                    // 验证恢复的正确性
                    if (!recoveredFromWorking.equals(system.secret) || !recoveredFromMain.equals(system.secret)) {
                        failureCount++;
                    } else {
                        successCount++;
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
     * JVM预热方法
     */
    private static void performWarmup() {
        System.out.println("执行JVM预热...");
        for (int i = 0; i < WARMUP_COUNT; i++) {
            try {
                DynamicThresholdSecretSharingVersion4App warmupSystem = new DynamicThresholdSecretSharingVersion4App(5, 3, false);
                warmupSystem.systemInitialization(warmupSystem.secret);
            } catch (Exception e) {
                // 忽略预热阶段的异常
            }
        }
        System.out.println("JVM预热完成\n");
    }

    /**
     * 主方法：程序入口点
     */
    public static void main(String[] args) {
        System.out.println("开始动态阈值秘密共享系统性能测试（严格按照文档方案优化）...");
        System.out.println("参数设置: n=" + NUM_PARTICIPANTS + ", 阈值=" + Arrays.toString(THRESHOLDS));
        System.out.println("实验次数: " + NUM_EXPERIMENTS);
        System.out.println("素数位数: " + PRIME_BIT_LENGTH);
        System.out.println("线程池大小: " + THREAD_POOL_SIZE);
        System.out.println();

        // JVM预热
        //performWarmup();

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