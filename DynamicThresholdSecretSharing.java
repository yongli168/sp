import javax.swing.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;

public class DynamicThresholdSecretSharing {
    // 实验参数
    private static final int NUM_PARTICIPANTS = 10;
    private static final int[] THRESHOLDS = {4, 5, 6};
    private static final int NUM_EXPERIMENTS = 1000;
    private static final int PRIME_BIT_LENGTH = 256;

    // 预热次数
    private static final int WARMUP_COUNT = 10;

    private BigInteger p; // 256位大素数
    private int n; // 参与者数量
    private int currentThreshold; // 当前阈值
    private BigInteger secret; // 秘密值
    private List<BigInteger> participantIDs; // 参与者ID列表

    // 系统状态
    private BivariatePolynomial mainPolynomial; // 主多项式
    private List<UnivariatePolynomial> mainShares; // 主份额
    private List<BigInteger> workingShares; // 工作份额

    // 性能统计
    private PerformanceStats stats;
    private boolean verbose; // 控制详细日志输出

    public DynamicThresholdSecretSharing(int n, int initialThreshold, boolean verbose) {
        this.n = n;
        this.currentThreshold = initialThreshold;
        this.p = generateLargePrime(PRIME_BIT_LENGTH);
        //this.p = BigInteger.valueOf(101);
        this.participantIDs = generateParticipantIDs(n);
        this.stats = new PerformanceStats();
        this.verbose = verbose;
    }

    // 生成大素数
    private BigInteger generateLargePrime(int bitLength) {
        long start = System.nanoTime();
        BigInteger prime = BigInteger.probablePrime(bitLength, new SecureRandom());
        long end = System.nanoTime();

        if (verbose) {
            System.out.println("生成 " + bitLength + " 位大素数: " + prime);
            System.out.printf("素数生成时间: %.3f ms\n", (end - start) / 1e6);
        }
        return prime;
    }

    // 生成参与者ID
    private List<BigInteger> generateParticipantIDs(int n) {
        List<BigInteger> ids = new ArrayList<>();
        for (int i = 1; i <= n; i++) {
            ids.add(BigInteger.valueOf(i));
        }
        return ids;
    }

    // 系统初始化
    public void systemInitialization(BigInteger secret) {
        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n=== 系统初始化开始 ===");
            System.out.println("秘密值 s = " + secret);
            System.out.println("有限域 GF(p), p = " + p);
            System.out.println("参与者数量 n = " + n);
            System.out.println("初始阈值 t = " + currentThreshold);
        }

        this.secret = secret;
        // 生成对称双变量多项式
        this.mainPolynomial = new BivariatePolynomial(currentThreshold, p, secret, verbose);

        if (verbose) {
            System.out.println("\n生成的主多项式:");
            System.out.println(mainPolynomial.toString());
        }

        // 生成主份额
        this.mainShares = new ArrayList<>();
        for (int i = 0; i < participantIDs.size(); i++) {
            BigInteger id = participantIDs.get(i);
            UnivariatePolynomial share = mainPolynomial.evaluateAtX(id);
            mainShares.add(share);

            if (verbose) {
                System.out.printf("参与者 P%d (ID=%d) 的主份额: %s\n", i + 1, id, share.toString());
            }
        }

        // 生成工作份额
        this.workingShares = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            BigInteger workingShare = mainShares.get(i).evaluate(BigInteger.ZERO);
            workingShares.add(workingShare);

            if (verbose) {
                System.out.printf("参与者 P%d 的初始工作份额: T%d = %s\n", i + 1, i + 1, workingShare);
            }
        }

        long endTime = System.nanoTime();
        stats.addInitTime(endTime - startTime);

        if (verbose) {
            System.out.println("=== 系统初始化完成 ===");
            System.out.printf("初始化总时间: %.3f ms\n", (endTime - startTime) / 1e6);
        }
    }

    // 阈值下调协议
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

    // 工作份额更新
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

            if (verbose) {
                System.out.printf("P%d: T_%d^(old) = %s, Δ(%d,0) = %s, T_%d^(new) = %s\n",
                        i + 1, i + 1, oldShare, i + 1, updateValue, i + 1, newShare);
            }
        }

        long endTime = System.nanoTime();
        stats.addShareUpdateTime(endTime - startTime);

        if (verbose) {
            System.out.println("=== 工作份额更新完成 ===");
            System.out.printf("工作份额更新总时间: %.3f ms\n", (endTime - startTime) / 1e6);
        }
    }

    // 主份额更新
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

            if (verbose) {
                System.out.printf("P%d 主份额更新:\n", i + 1);
                System.out.printf("  旧主份额: %s\n", oldMainShare.toString());
                System.out.printf("  更新多项式在 ID=%d 的值: %s\n", i + 1, updatePolyAtID.toString());
                System.out.printf("  新主份额: %s\n", newMainShare.toString());
            }
        }

        long endTime = System.nanoTime();
        stats.addShareUpdateTime(endTime - startTime);

        if (verbose) {
            System.out.println("=== 主份额更新完成 ===");
            System.out.printf("主份额更新总时间: %.3f ms\n", (endTime - startTime) / 1e6);
        }
    }

    // 秘密恢复
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

    // 计算拉格朗日系数
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

    // 计算恢复时的拉格朗日系数
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

    // 生成随机种子
    private BigInteger generateRandomSeed(String contextInfo, int round) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String input = "previous_seed" + contextInfo + round;
            byte[] hash = digest.digest(input.getBytes());
            return new BigInteger(1, hash).mod(p);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    // 生成更新多项式
    private BivariatePolynomial generateUpdatePolynomial(BigInteger seed, int threshold) {
        Random prng = new Random(seed.longValue());
        BivariatePolynomial updatePoly = new BivariatePolynomial(threshold, p, BigInteger.ZERO, false);

        // 设置随机系数，保持对称性和零常数项
        for (int i = 0; i < threshold; i++) {
            for (int j = i; j < threshold; j++) {
                if (i == 0 && j == 0) {
                    continue; // 保持常数项为0
                }
                byte[] randomBytes = new byte[32];
                prng.nextBytes(randomBytes);
                BigInteger coeff = new BigInteger(1, randomBytes).mod(p);
                updatePoly.setCoefficient(i, j, coeff);
                if (i != j) {
                    updatePoly.setCoefficient(j, i, coeff);
                }
            }
        }

        return updatePoly;
    }

    // 性能统计类
    public static class PerformanceStats {
        private List<Long> initTimes = new ArrayList<>();
        private List<Long> thresholdAdjustTimes = new ArrayList<>();
        private List<Long> shareUpdateTimes = new ArrayList<>();
        private List<Long> recoveryTimes = new ArrayList<>();

        public void addInitTime(long time) { initTimes.add(time); }
        public void addThresholdAdjustTime(long time) { thresholdAdjustTimes.add(time); }
        public void addShareUpdateTime(long time) { shareUpdateTimes.add(time); }
        public void addRecoveryTime(long time) { recoveryTimes.add(time); }

        public void printStats() {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("性能统计 (" + initTimes.size() + " 次实验)");
            System.out.println("=".repeat(60));

            System.out.printf("系统初始化平均时间: %.3f ms (标准差: %.3f ms)\n",
                    calculateAverage(initTimes) / 1e6, calculateStdDev(initTimes) / 1e6);
            System.out.printf("阈值调整平均时间: %.3f ms (标准差: %.3f ms)\n",
                    calculateAverage(thresholdAdjustTimes) / 1e6, calculateStdDev(thresholdAdjustTimes) / 1e6);
            System.out.printf("份额更新平均时间: %.3f ms (标准差: %.3f ms)\n",
                    calculateAverage(shareUpdateTimes) / 1e6, calculateStdDev(shareUpdateTimes) / 1e6);
            System.out.printf("秘密恢复平均时间: %.3f ms (标准差: %.3f ms)\n",
                    calculateAverage(recoveryTimes) / 1e6, calculateStdDev(recoveryTimes) / 1e6);

            // 输出详细时间分布
            System.out.println("\n时间分布 (ms):");
            System.out.printf("初始化: %s\n", formatTimeStats(initTimes));
            System.out.printf("阈值调整: %s\n", formatTimeStats(thresholdAdjustTimes));
            System.out.printf("份额更新: %s\n", formatTimeStats(shareUpdateTimes));
            System.out.printf("秘密恢复: %s\n", formatTimeStats(recoveryTimes));
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
    }

    // 双变量多项式类
    private static class BivariatePolynomial {
        private int degree;
        private BigInteger p;
        private BigInteger[][] coefficients;

        public BivariatePolynomial(int threshold, BigInteger p, BigInteger constantTerm, boolean verbose) {
            this.degree = threshold - 1;
            this.p = p;
            this.coefficients = new BigInteger[threshold][threshold];

            if (verbose) {
                System.out.println("构造 " + degree + " 次对称双变量多项式");
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
            for (int i = 0; i < threshold; i++) {
                for (int j = i; j < threshold; j++) {
                    if (i == 0 && j == 0) continue;
                    byte[] bytes = new byte[32];
                    random.nextBytes(bytes);
                    BigInteger coeff = new BigInteger(1, bytes).mod(p);
                    coefficients[i][j] = coeff;
                    coefficients[j][i] = coeff; // 对称性

                    if (verbose && i <= threshold && j <= threshold) { // 只输出前几个系数避免过多输出
                        System.out.printf("系数 a[%d][%d] = a[%d][%d] = %s\n",
                                i, j, j, i, coeff);
                    }
                }
            }

            if (verbose) {
                System.out.println("多项式构造完成，常数项 a[0][0] = " + coefficients[0][0]);
            }
        }

        public void setCoefficient(int i, int j, BigInteger value) {
            coefficients[i][j] = value.mod(p);
        }

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

    // 单变量多项式类
    private static class UnivariatePolynomial {
        private BigInteger[] coefficients;
        private BigInteger p;

        public UnivariatePolynomial(BigInteger[] coefficients, BigInteger p) {
            this.coefficients = coefficients;
            this.p = p;
        }

        public BigInteger evaluate(BigInteger x) {
            BigInteger result = BigInteger.ZERO;
            for (int i = 0; i < coefficients.length; i++) {
                BigInteger term = coefficients[i].multiply(x.pow(i)).mod(p);
                result = result.add(term).mod(p);
            }
            return result;
        }

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


    // 在DynamicThresholdSecretSharing类中添加
    public static void generatePerformanceChart() {
        // 收集性能数据
        Map<Integer, Map<String, Double>> chartData = new TreeMap<>();

        // 这里应该从实际的性能统计中获取数据
        // 示例数据 - 替换为真实数据
        Map<String, Double> t4Data = new HashMap<>();
        t4Data.put("系统初始化", 12.3);
        t4Data.put("阈值调整", 45.7);
        t4Data.put("工作份额更新", 8.9);
        t4Data.put("主份额更新", 10.1);
        t4Data.put("秘密恢复", 5.4);
        chartData.put(4, t4Data);

        Map<String, Double> t5Data = new HashMap<>();
        t5Data.put("系统初始化", 15.2);
        t5Data.put("阈值调整", 50.5);
        t5Data.put("工作份额更新", 9.9);
        t5Data.put("主份额更新", 11.3);
        t5Data.put("秘密恢复", 6.1);
        chartData.put(5, t5Data);

        Map<String, Double> t6Data = new HashMap<>();
        t6Data.put("系统初始化", 18.6);
        t6Data.put("阈值调整", 55.8);
        t6Data.put("工作份额更新", 10.5);
        t6Data.put("主份额更新", 12.7);
        t6Data.put("秘密恢复", 6.8);
        chartData.put(6, t6Data);

        // 创建并显示图表
        JFrame frame = new JFrame("图6.1 核心操作执行时间随阈值变化趋势");
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        PerformanceChart chart = new PerformanceChart();
        chart.setPerformanceData(chartData);
        frame.add(chart);

        frame.pack();
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    // JVM预热方法
    private static void performWarmup() {
        System.out.println("执行JVM预热...");
        for (int i = 0; i < WARMUP_COUNT; i++) {
            try {
                DynamicThresholdSecretSharingVersion1App warmupSystem =
                        new DynamicThresholdSecretSharingVersion1App(5, 3, false);
                //BigInteger warmupSecret = BigInteger.valueOf(42);
                warmupSystem.systemInitialization(warmupSystem.secret);
            } catch (Exception e) {
                // 忽略预热阶段的异常
            }
        }
        System.out.println("JVM预热完成\n");
    }

    // 运行实验
    public static void main(String[] args) {
        System.out.println("开始动态阈值秘密共享系统性能测试...");
        System.out.println("参数设置: n=" + NUM_PARTICIPANTS + ", 阈值=" + Arrays.toString(THRESHOLDS));
        System.out.println("实验次数: " + NUM_EXPERIMENTS);
        System.out.println("素数位数: " + PRIME_BIT_LENGTH);
        System.out.println();
        // JVM预热
        performWarmup();

        // 为每个阈值创建性能统计
        PerformanceStats[] thresholdStats = new PerformanceStats[THRESHOLDS.length];
        for (int i = 0; i < THRESHOLDS.length; i++) {
            thresholdStats[i] = new PerformanceStats();
        }

        for (int thresholdIdx = 0; thresholdIdx < THRESHOLDS.length; thresholdIdx++) {
            int threshold = THRESHOLDS[thresholdIdx];
            System.out.println("\n" + "=".repeat(80));
            System.out.println("测试阈值 t=" + threshold);
            System.out.println("=".repeat(80));

            for (int exp = 0; exp < NUM_EXPERIMENTS; exp++) {
                try {
                    boolean verbose = (exp == 0); // 只在第一次实验时输出详细日志

                    if (verbose) {
                        System.out.println("\n>>> 第 " + (exp + 1) + " 次实验 (详细日志模式) <<<");
                    } else if (exp % 20 == 0) {
                        System.out.println("进行第 " + (exp + 1) + " 次实验...");
                    }

                    // 创建系统实例
                    DynamicThresholdSecretSharing system = new DynamicThresholdSecretSharing(
                            NUM_PARTICIPANTS, threshold, verbose);

                    // 生成随机秘密
                    BigInteger secret = new BigInteger(PRIME_BIT_LENGTH, new SecureRandom()).mod(system.p);

                    // 1. 系统初始化
                    system.systemInitialization(secret);

                    // 2. 阈值调整 (下调)
                    if (threshold > 2) {
                        system.thresholdDecrease(threshold - 1);
                    }

                    // 3. 份额更新
                    system.workingShareUpdate("test_update", 1);
                    system.mainShareUpdate("test_update", 1);

                    // 4. 秘密恢复
                    List<Integer> recoveryParticipants = new ArrayList<>();
                    for (int i = 0; i < system.currentThreshold; i++) {
                        recoveryParticipants.add(i);
                    }
                    BigInteger recovered = system.secretRecovery(recoveryParticipants);

                    // 验证恢复的正确性
                    if (!recovered.equals(secret)) {
                        System.out.println("警告: 秘密恢复验证失败! 期望: " + secret + ", 实际: " + recovered);
                    } else if (verbose) {
                        System.out.println("✓ 秘密恢复验证成功");
                    }

                    // 收集统计信息
                    thresholdStats[thresholdIdx].addInitTime(system.stats.initTimes.get(0));
                    if (system.stats.thresholdAdjustTimes.size() > 0) {
                        thresholdStats[thresholdIdx].addThresholdAdjustTime(system.stats.thresholdAdjustTimes.get(0));
                    }
                    if (system.stats.shareUpdateTimes.size() > 0) {
                        // 取平均值，因为可能有多次更新
                        long avgUpdateTime = (long) system.stats.shareUpdateTimes.stream()
                                .mapToLong(Long::longValue).average().orElse(0);
                        thresholdStats[thresholdIdx].addShareUpdateTime(avgUpdateTime);
                    }
                    if (system.stats.recoveryTimes.size() > 0) {
                        thresholdStats[thresholdIdx].addRecoveryTime(system.stats.recoveryTimes.get(0));
                    }

                } catch (Exception e) {
                    System.out.println("实验 " + (exp + 1) + " 失败: " + e.getMessage());
                    e.printStackTrace();
                }
            }

            // 输出当前阈值的统计结果
            System.out.println("\n>>> 阈值 t=" + threshold + " 的统计结果:");
            thresholdStats[thresholdIdx].printStats();
        }

        // 输出总体统计
        System.out.println("\n" + "=".repeat(80));
        System.out.println("总体性能统计");
        System.out.println("=".repeat(80));

        for (int i = 0; i < THRESHOLDS.length; i++) {
            System.out.println("\n阈值 t=" + THRESHOLDS[i] + ":");
            thresholdStats[i].printStats();
        }


        /*SwingUtilities.invokeLater(() -> {
            generatePerformanceChart();
        });*/

        System.out.println("\n所有测试完成!");

        // 生成图表数据摘要
        generateChartSummary(thresholdStats);
    }



    // 生成图表数据摘要
    private static void generateChartSummary(PerformanceStats[] stats) {
        System.out.println("\n" + "=".repeat(80));
        System.out.println("图表数据摘要 (用于图6.1)");
        System.out.println("=".repeat(80));

        System.out.println("\n阈值(t) | 系统初始化(ms) | 阈值下调(ms) | 工作份额更新(ms) | 主份额更新(ms)");
        System.out.println("--------|---------------|-------------|-----------------|---------------");

        for (int i = 0; i < THRESHOLDS.length; i++) {
            double initTime = stats[i].calculateAverage(stats[i].initTimes) / 1e6;
            double thresholdTime = stats[i].thresholdAdjustTimes.isEmpty() ? 0 :
                    stats[i].calculateAverage(stats[i].thresholdAdjustTimes) / 1e6;
            double updateTime = stats[i].shareUpdateTimes.isEmpty() ? 0 :
                    stats[i].calculateAverage(stats[i].shareUpdateTimes) / 1e6;

            System.out.printf("   %d    |     %8.3f   |   %8.3f   |      %8.3f    |     %8.3f\n",
                    THRESHOLDS[i], initTime, thresholdTime, updateTime, updateTime);
        }
    }
}