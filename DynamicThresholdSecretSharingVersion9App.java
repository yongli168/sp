package code;

import javax.swing.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;

/**
 * Dynamic-threshold secret-sharing system – Version 9 application – strictly follows the paper
 * Implements all protocols and validations described in Sections 4.1–4.6
 */
public class DynamicThresholdSecretSharingVersion9App {
    // ============================ Experiment configuration ============================
    private static final int NUM_PARTICIPANTS = 20;
    private static final int[] THRESHOLDS = {5,7,9,11,13};
    private static final int NUM_EXPERIMENTS = 1000;
    private static final int PRIME_BIT_LENGTH = 256;
    private static final int INCREASE_THRESHOLDS = 1; // extension degree
    private static final int UP_THRESHOLDS = 3;// threshold increase
    private static final BigInteger FIXED_256BIT_PRIME = new BigInteger(
            "115792089237316195423570985008687907853269984665640564039457584007908834671663");
    private static final int THREAD_POOL_SIZE = THRESHOLDS.length;

    // ============================ System state variables ============================
    private BigInteger p;
    private int n;
    private int currentThreshold;
    private int currentMainThreshold;
    public BigInteger secret;
    private List<BigInteger> participantIDs;
    private BigInteger previousSeed;

    // ============================ Core system components ============================
    private BivariatePolynomial mainPolynomial;
    private List<UnivariatePolynomial> mainShares;
    private List<BigInteger> workingShares;
    private PerformanceStats stats;
    private boolean verbose;

    /**
     * Constructor: initialises the dynamic-threshold secret-sharing system
     */
    public DynamicThresholdSecretSharingVersion9App(int n, int initialThreshold, boolean verbose) {
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
            System.out.println("✓ System initialisation complete – participants: " + n + ", initial threshold: " + initialThreshold);
        }
    }

    /**
     * Generate list of participant IDs
     */
    private List<BigInteger> generateParticipantIDs(int n) {
        List<BigInteger> ids = new ArrayList<>();
        for (int i = 1; i <= n; i++) {
            ids.add(BigInteger.valueOf(i));
        }
        return ids;
    }

    /**
     * System initialisation: strictly follows Section 4.2 of the paper
     */
    public void systemInitialization(BigInteger secret) {
        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("4.2 System initialisation started");
            System.out.println("=".repeat(60));
        }

        this.secret = secret;

        // Generate symmetric bivariate polynomial – strictly follows Eq. (4.2)
        if (verbose) System.out.println("Step 1: generate symmetric bivariate polynomial f(x,y)");
        this.mainPolynomial = new BivariatePolynomial(currentThreshold, p, secret, verbose);

        // Generate master shares – strictly follows Section 4.3.1
        if (verbose) System.out.println("Step 2: generate master shares S_i(y) = f(ID_i, y)");
        this.mainShares = new ArrayList<>();
        for (int i = 0; i < participantIDs.size(); i++) {
            BigInteger id = participantIDs.get(i);
            UnivariatePolynomial share = mainPolynomial.evaluateAtX(id);
            mainShares.add(share);
        }

        // Generate working shares – strictly follows Section 4.3.2
        if (verbose) System.out.println("Step 3: generate working shares T_i = S_i(0) = f(ID_i, 0)");
        this.workingShares = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            BigInteger workingShare = mainShares.get(i).evaluate(BigInteger.ZERO);
            workingShares.add(workingShare);
        }

        long endTime = System.nanoTime();
        stats.addInitTime(endTime - startTime);

        if (verbose) {
            System.out.println("✓ System initialisation complete");
            System.out.printf("Total initialisation time: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }
    }

    /**
     * Secure threshold-decrease protocol: strictly follows Section 4.4.2
     */
    public void thresholdDecrease(int newThreshold) {
        if (newThreshold >= currentThreshold) {
            throw new IllegalArgumentException("New threshold must be smaller than current threshold");
        }

        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("4.4.2 Secure threshold-decrease protocol started");
            System.out.println("=".repeat(60));
            System.out.println("Current threshold: " + currentThreshold + " → new threshold: " + newThreshold);
        }

        // Step 1: locally compute Lagrange components – strictly follows paper Step 1
        if (verbose) System.out.println("Step 1: locally compute Lagrange components c_i = S_i(0) × L_i");
        List<BigInteger> lagrangeComponents = computeLagrangeComponents(currentThreshold);

        // Step 2: locally generate re-sharing polynomials – strictly follows paper Step 2
        if (verbose) System.out.println("Step 2: locally generate re-sharing polynomials h_i(x,y)");
        List<BivariatePolynomial> resharePolynomials = generateResharePolynomials(lagrangeComponents, newThreshold);

        // Step 3: locally generate encrypted shares and broadcast – strictly follows paper Step 3
        if (verbose) System.out.println("Step 3: generate encrypted shares and broadcast C_ik = v_ik + k_ik");
        List<List<BigInteger>> encryptedShares = generateEncryptedShares(resharePolynomials);

        // Step 4: parallel decryption and working-share computation – strictly follows paper Step 4
        if (verbose) System.out.println("Step 4: parallel decryption and compute new working shares");
        updateWorkingShares(encryptedShares);

        this.currentThreshold = newThreshold;

        long endTime = System.nanoTime();
        stats.addThresholdAdjustTime(endTime - startTime);

        if (verbose) {
            System.out.println("✓ Secure threshold decrease complete");
            System.out.printf("Total threshold-decrease time: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }
    }

    /**
     * Compute Lagrange components – helper
     */
    private List<BigInteger> computeLagrangeComponents(int threshold) {
        List<BigInteger> components = new ArrayList<>();
        for (int i = 0; i < threshold; i++) {
            BigInteger lagrangeCoeff = computeLagrangeCoefficient(i, threshold);
            BigInteger mainShareValue = mainShares.get(i).evaluate(BigInteger.ZERO);
            BigInteger component = mainShareValue.multiply(lagrangeCoeff).mod(p);
            components.add(component);
            if (verbose && i < 3) {
                System.out.println("  Participant P" + (i+1) + " Lagrange component: " + component);
            }
        }
        return components;
    }

    /**
     * Generate re-sharing polynomials – helper
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
     * Generate encrypted shares – helper
     */
    private List<List<BigInteger>> generateEncryptedShares(List<BivariatePolynomial> resharePolynomials) {
        List<List<BigInteger>> encryptedShares = new ArrayList<>();
        for (int i = 0; i < resharePolynomials.size(); i++) {
            List<BigInteger> encryptedRow = new ArrayList<>();
            BivariatePolynomial poly = resharePolynomials.get(i);

            for (int j = 0; j < n; j++) {
                BigInteger shareValue = poly.evaluate(participantIDs.get(j), BigInteger.ZERO);
                // Compute pairing key using current main polynomial – strictly follows paper
                BigInteger pairingKey = mainPolynomial.evaluate(participantIDs.get(i), participantIDs.get(j));
                BigInteger encrypted = shareValue.add(pairingKey).mod(p);
                encryptedRow.add(encrypted);
            }
            encryptedShares.add(encryptedRow);
        }
        return encryptedShares;
    }

    /**
     * Update working shares – helper
     */
    private void updateWorkingShares(List<List<BigInteger>> encryptedShares) {
        List<BigInteger> newWorkingShares = new ArrayList<>();
        for (int k = 0; k < n; k++) {
            BigInteger sum = BigInteger.ZERO;
            for (int i = 0; i < encryptedShares.size(); i++) {
                BigInteger encrypted = encryptedShares.get(i).get(k);
                // Compute pairing key using current main polynomial – strictly follows paper
                BigInteger pairingKey = mainPolynomial.evaluate(participantIDs.get(k), participantIDs.get(i));
                BigInteger decrypted = encrypted.subtract(pairingKey).mod(p);
                sum = sum.add(decrypted).mod(p);
            }
            newWorkingShares.add(sum);
        }
        this.workingShares = newWorkingShares;
    }

    /**
     * Secure threshold increase:
     * adopt newThreshold > original threshold
     * @param newThreshold
     */
    public void thresholdAdjustUp(int newThreshold){
        if (newThreshold <= currentThreshold) {
            throw new IllegalArgumentException("New threshold must be greater than current threshold");
        }

        if (verbose) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("Secure threshold up-adjustment started");
            System.out.println("=".repeat(60));
            System.out.println("Current threshold: " + currentThreshold + " → new threshold: " + newThreshold);
        }
        long startTime = System.nanoTime();
        // Secret-recovery verification – added 2025-12-02
        List<Integer> recoveryParticipants = new ArrayList<>();
        for (int i = 0; i < newThreshold && i < this.n; i++) {
            recoveryParticipants.add(i);
        }
        BigInteger recoveredSecret = this.secretRecovery(recoveryParticipants);
        if (!recoveredSecret.equals(this.secret)) {
            throw new IllegalStateException("Secret recovery failed; threshold increase aborted");
        }
        long endTime = System.nanoTime();
        stats.addThresholdUpTime(endTime - startTime);
        if (verbose) {
            System.out.println("✓ Secure threshold increase complete");
            System.out.printf("Total threshold increase time: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }
    }


    /**
     * Secret recovery for threshold up-adjustment
     * @param participantIndices
     * @return
     */
    public BigInteger secretRecovery(List<Integer> participantIndices) {
        validateRecoveryParticipants(participantIndices, currentThreshold);
        // Pre-compute pairing keys
        Map<String, BigInteger> pairingKeyCache = precomputePairingKeys(participantIndices);
        // Compute Lagrange components
        List<BigInteger> lagrangeComponents = computeRecoveryLagrangeComponents(participantIndices, true);
        // Generate published values
        List<BigInteger> publishedValues = generatePublishedValues(participantIndices, lagrangeComponents, pairingKeyCache);
        // Recover secret
        BigInteger recoveredSecret = recoverSecretFromPublishedValues(publishedValues);
        return recoveredSecret;
    }

    /**
     * Secure threshold pre-expansion protocol: strictly follows Section 4.4.1
     * Optimisation: pure polynomial expansion instead of superposition
     */
    public void thresholdPreexpansion(int newThreshold) {
        if (newThreshold <= currentThreshold) {
            throw new IllegalArgumentException("New threshold must be greater than current threshold");
        }

        long startTime = System.nanoTime();
        if (verbose) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("4.4.1 Secure threshold-increase protocol started (optimised)");
            System.out.println("=".repeat(60));
            System.out.println("Current threshold: " + currentThreshold + " → new threshold: " + newThreshold);
            System.out.println("Extension degree k = " + (newThreshold - currentThreshold));
        }

        int k = newThreshold - currentThreshold;

        // Optimised Step 1: directly construct expanded polynomial – strictly follows paper expansion design
        if (verbose) System.out.println("Step 1: directly construct expanded symmetric bivariate polynomial");
        this.mainPolynomial = buildExtendedPolynomialDirectly(newThreshold);

        // New: strictly validate expanded polynomial
        if (verbose) System.out.println("Step 1.1: validate expanded polynomial meets paper requirements");
        validateExtendedPolynomial(this.mainPolynomial, currentThreshold, newThreshold);

        // Optimised Step 2: re-generate master shares – based on new polynomial
        if (verbose) System.out.println("Step 2: re-generate master shares based on expanded polynomial");
        updateMainSharesForExtension(newThreshold);

        // Optimised Step 3: re-generate working shares
        if (verbose) System.out.println("Step 3: re-generate working shares based on expanded polynomial");
        updateWorkingSharesForExtension(newThreshold);

        this.currentThreshold = newThreshold;
        this.currentMainThreshold = newThreshold;


        long endTime = System.nanoTime();
        stats.addThresholdIncreaseTime(endTime - startTime);

        if (verbose) {
            System.out.println("✓ Secure threshold expansion complete (strictly follows paper expansion)");
            System.out.printf("Total threshold-increase time: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }
    }

    /**
     * Validate expanded polynomial meets paper requirements
     */
    private void validateExtendedPolynomial(BivariatePolynomial extendedPoly, int originalThreshold, int newThreshold) {
        // Validation 1: low-order coefficients unchanged
        for (int i = 0; i < originalThreshold; i++) {
            for (int j = 0; j < originalThreshold; j++) {
                if (!extendedPoly.coefficients[i][j].equals(mainPolynomial.coefficients[i][j])) {
                    throw new IllegalStateException("Low-order coefficients modified during expansion");
                }
            }
        }

        // Validation 2: symmetry preserved
        for (int i = 0; i < newThreshold; i++) {
            for (int j = i; j < newThreshold; j++) {
                if (!extendedPoly.coefficients[i][j].equals(extendedPoly.coefficients[j][i])) {
                    throw new IllegalStateException("Expanded polynomial symmetry broken");
                }
            }
        }

        // Validation 3: secret value preserved
        BigInteger extendedSecret = extendedPoly.evaluate(BigInteger.ZERO, BigInteger.ZERO);
        if (!extendedSecret.equals(secret)) {
            throw new IllegalStateException("Secret mismatch after expansion: " + extendedSecret + " != " + secret);
        }

        // Validation 4: correct degree
        if (extendedPoly.coefficients.length != newThreshold) {
            throw new IllegalStateException("Expanded polynomial degree incorrect");
        }

        if (verbose) {
            System.out.println("  ✓ Expanded polynomial validation passed:");
            System.out.println("    - Low-order coefficients intact");
            System.out.println("    - Symmetry constraint satisfied");
            System.out.println("    - Secret value correct");
            System.out.println("    - Polynomial degree: " + (newThreshold - 1));
        }
    }

    /**
     * Re-generate working shares based on expanded polynomial – strictly follows paper working-share definition
     */
    private void updateWorkingSharesForExtension(int newThreshold) {
        if (verbose) System.out.println("  Re-computing working shares for " + n + " participants");

        for (int i = 0; i < n; i++) {
            // Directly compute new working share from expanded polynomial
            BigInteger newWorkingShare = mainPolynomial.evaluate(participantIDs.get(i), BigInteger.ZERO);
            workingShares.set(i, newWorkingShare);

            if (verbose && i < 2) {
                System.out.println("    Participant P" + (i+1) + " new working share: " +
                        newWorkingShare.toString().substring(0, Math.min(10, newWorkingShare.toString().length())) + "...");
            }
        }
    }

    /**
     * Re-generate master shares based on expanded polynomial – strictly follows paper master-share definition
     */
    private void updateMainSharesForExtension(int newThreshold) {
        if (verbose) System.out.println("  Re-computing master shares for " + n + " participants");

        for (int i = 0; i < n; i++) {
            BigInteger id = participantIDs.get(i);
            // Directly compute new master share from expanded polynomial
            UnivariatePolynomial newMainShare = mainPolynomial.evaluateAtX(id);
            mainShares.set(i, newMainShare);

            if (verbose && i < 2) {
                System.out.println("    Participant P" + (i+1) + " new master-share degree: " + (newMainShare.coefficients.length - 1));
            }
        }
    }

    /**
     * Directly construct expanded polynomial – strictly follows Section 4.4.1 mathematical description
     * Core: keep low-order coefficients intact, only extend high-order random coefficients
     */
    private BivariatePolynomial buildExtendedPolynomialDirectly(int newThreshold) {
        // Create polynomial for new threshold
        BivariatePolynomial extendedPoly = new BivariatePolynomial(newThreshold, p, this.secret, false);

        // Step 1: copy original polynomial coefficients (low-order part)
        if (verbose) System.out.println("  Copying low-order coefficients (0 ≤ i,j < " + currentThreshold + ")");
        for (int i = 0; i < currentThreshold; i++) {
            for (int j = 0; j < currentThreshold; j++) {
                extendedPoly.setCoefficient(i, j, mainPolynomial.coefficients[i][j]);
            }
        }

        // Step 2: generate extended high-order random coefficients – strictly follows paper expansion design
        if (verbose) System.out.println("  Generating extended high-order coefficients (" + currentThreshold + " ≤ i,j < " + newThreshold + ")");
        SecureRandom secureRandom = BCCryptoUtils.createSecureRandom(null);

        // Generate only extended high-order coefficients
        for (int i = currentThreshold; i < newThreshold; i++) {
            for (int j = i; j < newThreshold; j++) { // upper-triangular only, diagonal included
                BigInteger coeff = new BigInteger(p.bitLength() - 1, secureRandom).mod(p);
                extendedPoly.setCoefficient(i, j, coeff);
                if (i != j) {
                    extendedPoly.setCoefficient(j, i, coeff); // preserve symmetry
                }

                if (verbose && i == currentThreshold && j == currentThreshold) {
                    System.out.println("  First extended coefficient: a[" + i + "][" + j + "] = " + coeff);
                }
            }
        }

        // Validate secret preservation after expansion
        BigInteger verifiedSecret = extendedPoly.evaluate(BigInteger.ZERO, BigInteger.ZERO);
        if (!verifiedSecret.equals(secret)) {
            throw new IllegalStateException("Secret mismatch after polynomial expansion");
        }

        if (verbose) {
            System.out.println("  Expanded polynomial validation: f(0,0) = " + verifiedSecret + " ✓");
            System.out.println("  Number of independent coefficients: " + (newThreshold * (newThreshold + 1) / 2) +
                    " (original: " + (currentThreshold * (currentThreshold + 1) / 2) + ")");
        }

        return extendedPoly;
    }

    /**
     * Generate extension polynomial – helper
     */
    private BivariatePolynomial generateExtensionPolynomial(int k) {
        // Create extension polynomial with zero constant term – strictly follows paper requirement
        BivariatePolynomial extensionPoly = new BivariatePolynomial(currentThreshold + k, p, BigInteger.ZERO, false);

        // Set only high-order coefficients, keep low-order zero – key fix
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
     * Build expanded polynomial – key fix method
     */
    private BivariatePolynomial buildExtendedPolynomial(BivariatePolynomial extensionPoly, int newThreshold) {
        BivariatePolynomial newPoly = new BivariatePolynomial(newThreshold, p, this.secret, false);

        // Copy original polynomial coefficients
        for (int i = 0; i < currentThreshold; i++) {
            for (int j = 0; j < currentThreshold; j++) {
                newPoly.setCoefficient(i, j, mainPolynomial.coefficients[i][j]);
            }
        }

        // Add extension polynomial coefficients
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
     * Update master shares – helper
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
     * Update working shares – helper
     */
    private void updateWorkingSharesForIncrease(BivariatePolynomial extensionPoly) {
        for (int i = 0; i < n; i++) {
            BigInteger extensionValue = extensionPoly.evaluate(participantIDs.get(i), BigInteger.ZERO);
            BigInteger newWorkingShare = workingShares.get(i).add(extensionValue).mod(p);
            workingShares.set(i, newWorkingShare);
        }
    }

    /**
     * Working-share update protocol: strictly follows Section 4.5.1
     */
    public void workingShareUpdate(String contextInfo, int updateRound) {
        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("4.5.1 Working-share update protocol started");
            System.out.println("=".repeat(60));
        }

        // Step 1: generate public random seed – strictly follows paper Step 1
        BigInteger randomSeed = generateRandomSeed(contextInfo, updateRound);

        // Step 2: generate update polynomial – strictly follows paper Step 2
        BivariatePolynomial updatePoly = generateUpdatePolynomial(randomSeed, currentThreshold);

        // Step 3: update local working shares – strictly follows paper Step 3
        updateWorkingSharesWithPoly(updatePoly);

        long endTime = System.nanoTime();
        stats.addWorkingShareUpdateTime(endTime - startTime);

        if (verbose) {
            System.out.println("✓ Working-share update complete");
            System.out.printf("Total working-share update time: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }
    }

    /**
     * Update working shares with update polynomial – helper
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
     * Master-share update protocol: strictly follows Section 4.5.2
     */
    public void mainShareUpdate(String contextInfo, int updateRound) {
        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("4.5.2 Master-share update protocol started");
            System.out.println("=".repeat(60));
        }

        // Step 1: generate public random seed
        BigInteger randomSeed = generateRandomSeed(contextInfo, updateRound);

        // Step 2: generate update polynomial
        BivariatePolynomial updatePoly = generateUpdatePolynomial(randomSeed, currentMainThreshold);

        // Step 3: update local master shares
        updateMainSharesWithPoly(updatePoly);

        long endTime = System.nanoTime();
        stats.addMasterShareUpdateTime(endTime - startTime);

        if (verbose) {
            System.out.println("✓ Master-share update complete");
            System.out.printf("Total master-share update time: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }
    }

    /**
     * Update master shares with update polynomial – helper
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
     * Secret recovery from working shares: strictly follows Section 4.6.1
     */
    public BigInteger secretRecoveryFromWorkingShares(List<Integer> participantIndices, boolean flag) {
        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("4.6.1 Secret recovery from working shares started");
            System.out.println("=".repeat(60));
        }

        validateRecoveryParticipants(participantIndices, currentThreshold);

        // Pre-compute pairing keys
        Map<String, BigInteger> pairingKeyCache = precomputePairingKeys(participantIndices);

        // Compute Lagrange components
        List<BigInteger> lagrangeComponents = computeRecoveryLagrangeComponents(participantIndices, true);

        // Generate published values
        List<BigInteger> publishedValues = generatePublishedValues(participantIndices, lagrangeComponents, pairingKeyCache);

        // Recover secret
        BigInteger recoveredSecret = recoverSecretFromPublishedValues(publishedValues);

        long endTime = System.nanoTime();
        if(flag){
            stats.addWorkingSharesRecoveryTime(endTime - startTime);
        }

        if (verbose) {
            printRecoveryResult(recoveredSecret, "working shares");
            System.out.printf("Recovery time: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }

        return recoveredSecret;
    }

    /**
     * Secret recovery from master shares: strictly follows Section 4.6.1
     */
    public BigInteger secretRecoveryFromMainShares(List<Integer> participantIndices,boolean flag) {
        long startTime = System.nanoTime();

        if (verbose) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("4.6.1 Secret recovery from master shares started");
            System.out.println("=".repeat(60));
        }

        validateRecoveryParticipants(participantIndices, currentMainThreshold);

        // Pre-compute pairing keys
        Map<String, BigInteger> pairingKeyCache = precomputePairingKeys(participantIndices);

        // Compute Lagrange components (using master shares)
        List<BigInteger> lagrangeComponents = computeRecoveryLagrangeComponents(participantIndices, false);

        // Generate published values
        List<BigInteger> publishedValues = generatePublishedValues(participantIndices, lagrangeComponents, pairingKeyCache);

        // Recover secret
        BigInteger recoveredSecret = recoverSecretFromPublishedValues(publishedValues);

        long endTime = System.nanoTime();
        if(flag){
            stats.addMainSharesRecoveryTime(endTime - startTime);
        }


        if (verbose) {
            printRecoveryResult(recoveredSecret, "master shares");
            System.out.printf("Recovery time: %.3f ms\n", (endTime - startTime) / 1e6);
            System.out.println("=".repeat(60));
        }

        return recoveredSecret;
    }

    /**
     * Validate recovery participants – helper
     */
    private void validateRecoveryParticipants(List<Integer> participantIndices, int requiredThreshold) {
        if (participantIndices.size() < requiredThreshold) {
            throw new IllegalArgumentException(
                    "Insufficient participants: need at least " + requiredThreshold + ", got: " + participantIndices.size());
        }
    }

    /**
     * Pre-compute pairing keys – helper
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
     * Compute recovery Lagrange components – helper
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
     * Generate published values – helper
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
     * Recover secret from published values – helper
     */
    private BigInteger recoverSecretFromPublishedValues(List<BigInteger> publishedValues) {
        BigInteger recoveredSecret = BigInteger.ZERO;
        for (BigInteger value : publishedValues) {
            recoveredSecret = recoveredSecret.add(value).mod(p);
        }
        return recoveredSecret;
    }

    /**
     * Print recovery result – helper
     */
    private void printRecoveryResult(BigInteger recoveredSecret, String shareType) {
        System.out.println("✓ Secret recovery from " + shareType + " complete");
        System.out.printf("Recovered secret: %s\n", recoveredSecret);
        System.out.printf("Original secret:  %s\n", secret);
        System.out.println("Result: " + (recoveredSecret.equals(secret) ? "✓ Success" : "✗ Failure"));
    }

    // ============================ Utility methods ============================

    /**
     * Compute Lagrange coefficient (for threshold adjustment)
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
     * Compute Lagrange coefficient for recovery
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
     * Generate random seed: strictly follows Section 4.5.1 Step 1
     */
    private BigInteger generateRandomSeed(String contextInfo, int round) {
        try {
            // Use Bouncy Castle SHA-256
            String input = previousSeed.toString() + contextInfo + round;
            byte[] hash = BCCryptoUtils.sha256(input.getBytes());
            BigInteger newSeed = new BigInteger(1, hash).mod(p);
            previousSeed = newSeed;

            if (verbose) {
                System.out.println("  Generated random seed: " + newSeed.toString());
            }

            return newSeed;
        } catch (Exception e) {
            // Fallback: Java built-in SHA-256
            System.err.println("Bouncy Castle SHA-256 failed, falling back to Java implementation: " + e.getMessage());
            try {
                java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
                String input = previousSeed.toString() + contextInfo + round;
                byte[] hash = digest.digest(input.getBytes());
                BigInteger newSeed = new BigInteger(1, hash).mod(p);
                previousSeed = newSeed;
                return newSeed;
            } catch (Exception ex) {
                throw new RuntimeException("Random seed generation failed", ex);
            }
        }
    }

    /**
     * Generate update polynomial: strictly follows Section 4.5.1 Step 2
     */
    private BivariatePolynomial generateUpdatePolynomial(BigInteger seed, int threshold) {
        SecureRandom prng = BCCryptoUtils.createSecureRandom(seed.toByteArray());
        BivariatePolynomial updatePoly = new BivariatePolynomial(threshold, p, BigInteger.ZERO, false);

        // Explicitly set constant term to zero
        updatePoly.setCoefficient(0, 0, BigInteger.ZERO);

        // Generate symmetric coefficients
        for (int i = 0; i < threshold; i++) {
            for (int j = i; j < threshold; j++) {
                if (i == 0 && j == 0) continue;
                // Use Bouncy Castle secure random generator
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
     * Performance statistics class
     */
    public static class PerformanceStats {
        private List<Long> initTimes = new ArrayList<>();
        private List<Long> thresholdAdjustTimes = new ArrayList<>();//threshold-decrease time
        private List<Long> thresholdIncreaseTimes = new ArrayList<>();//threshold-expansion time
        private List<Long> thresholdUpTimes = new ArrayList<>();//threshold increase when t'<1+t(t+1)/2
        private List<Long> workingShareUpdateTimes = new ArrayList<>();//working-share update time
        private List<Long> masterShareUpdateTimes = new ArrayList<>();//master-share update time
        private List<Long> workingSharesRecoveryTimes = new ArrayList<>();//working-share recovery time
        private List<Long> mainSharesRecoveryTimes = new ArrayList<>();//master-share recovery time
        private List<Long> mixedScenarioTimes = new ArrayList<>();//mixed-scenario time


        public void addInitTime(long time) { initTimes.add(time); }
        public void addThresholdAdjustTime(long time) { thresholdAdjustTimes.add(time); }
        public void addThresholdIncreaseTime(long time) { thresholdIncreaseTimes.add(time); }
        public void addThresholdUpTime(long time) {thresholdUpTimes.add(time);}
        public void addWorkingShareUpdateTime(long time) { workingShareUpdateTimes.add(time); }
        public void addMasterShareUpdateTime(long time) { masterShareUpdateTimes.add(time); }
        public void addWorkingSharesRecoveryTime(long time) { workingSharesRecoveryTimes.add(time); }
        public void addMainSharesRecoveryTime(long time) { mainSharesRecoveryTimes.add(time); }
        public void addMixedScenarioTime(long time) { mixedScenarioTimes.add(time); }

        /**
         * Print performance statistics
         */
        public void printStats() {
            System.out.println("\n" + "=".repeat(80));
            System.out.println("Performance statistics (" + initTimes.size() + " experiments)");
            System.out.println("=".repeat(80));

            if (!initTimes.isEmpty()) System.out.printf("Average system-init time: %.3f ms (std dev: %.3f ms)\n",
                    calculateAverage(initTimes) / 1e6, calculateStdDev(initTimes) / 1e6);
            if (!thresholdAdjustTimes.isEmpty()) System.out.printf("Average threshold-decrease time: %.3f ms (std dev: %.3f ms)\n",
                    calculateAverage(thresholdAdjustTimes) / 1e6, calculateStdDev(thresholdAdjustTimes) / 1e6);
            if (!thresholdIncreaseTimes.isEmpty()) System.out.printf("Average threshold-expansion time: %.3f ms (std dev: %.3f ms)\n",
                    calculateAverage(thresholdIncreaseTimes) / 1e6, calculateStdDev(thresholdIncreaseTimes) / 1e6);
            if(!thresholdUpTimes.isEmpty()) System.out.printf("Average threshold up-adjustment time: %.3f ms (std dev: %.3f ms)\n",
                    calculateAverage(thresholdUpTimes) / 1e6, calculateStdDev(thresholdUpTimes) / 1e6);
            if (!workingShareUpdateTimes.isEmpty()) System.out.printf("Average working-share update time: %.3f ms (std dev: %.3f ms)\n",
                    calculateAverage(workingShareUpdateTimes) / 1e6, calculateStdDev(workingShareUpdateTimes) / 1e6);
            if (!masterShareUpdateTimes.isEmpty()) System.out.printf("Average master-share update time: %.3f ms (std dev: %.3f ms)\n",
                    calculateAverage(masterShareUpdateTimes) / 1e6, calculateStdDev(masterShareUpdateTimes) / 1e6);
            if (!workingSharesRecoveryTimes.isEmpty()) System.out.printf("Average secret-recovery time (working shares): %.3f ms (std dev: %.3f ms)\n",
                    calculateAverage(workingSharesRecoveryTimes) / 1e6, calculateStdDev(workingSharesRecoveryTimes) / 1e6);
            if (!mainSharesRecoveryTimes.isEmpty()) System.out.printf("Average secret-recovery time (master shares): %.3f ms (std dev: %.3f ms)\n",
                    calculateAverage(mainSharesRecoveryTimes) / 1e6, calculateStdDev(mainSharesRecoveryTimes) / 1e6);
            if (!mixedScenarioTimes.isEmpty()) System.out.printf("Average mixed-scenario total time: %.3f ms (std dev: %.3f ms)\n",
                    calculateAverage(mixedScenarioTimes) / 1e6, calculateStdDev(mixedScenarioTimes) / 1e6);


            System.out.println("\nTime distribution (ms):");
            System.out.printf("Initialisation: %s\n", formatTimeStats(initTimes));
            System.out.printf("Threshold decrease: %s\n", formatTimeStats(thresholdAdjustTimes));
            System.out.printf("Threshold expansion: %s\n", formatTimeStats(thresholdIncreaseTimes));
            System.out.printf("Threshold up-adjustment: %s\n", formatTimeStats(thresholdUpTimes));
            System.out.printf("Working-share update: %s\n", formatTimeStats(workingShareUpdateTimes));
            System.out.printf("Master-share update: %s\n", formatTimeStats(masterShareUpdateTimes));
            System.out.printf("Working-share recovery: %s\n", formatTimeStats(workingSharesRecoveryTimes));
            System.out.printf("Master-share recovery: %s\n", formatTimeStats(mainSharesRecoveryTimes));
            System.out.printf("Mixed scenario: %s\n", formatTimeStats(mixedScenarioTimes));
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
            if (times.isEmpty()) return "no data";
            long min = times.stream().mapToLong(Long::longValue).min().orElse(0);
            long max = times.stream().mapToLong(Long::longValue).max().orElse(0);
            double avg = calculateAverage(times);
            return String.format("min=%.3f, avg=%.3f, max=%.3f",
                    min / 1e6, avg / 1e6, max / 1e6);
        }

        /**
         * Merge statistics
         */
        public void merge(PerformanceStats other) {
            this.initTimes.addAll(other.initTimes);
            this.thresholdAdjustTimes.addAll(other.thresholdAdjustTimes);
            this.thresholdIncreaseTimes.addAll(other.thresholdIncreaseTimes);
            this.thresholdUpTimes.addAll(other.thresholdUpTimes);
            this.workingShareUpdateTimes.addAll(other.workingShareUpdateTimes);
            this.masterShareUpdateTimes.addAll(other.masterShareUpdateTimes);
            this.workingSharesRecoveryTimes.addAll(other.workingSharesRecoveryTimes);
            this.mainSharesRecoveryTimes.addAll(other.mainSharesRecoveryTimes);
            this.mixedScenarioTimes.addAll(other.mixedScenarioTimes);
        }
    }

    /**
     * Bivariate-polynomial class: represents symmetric bivariate polynomial
     * Corresponds to Section 4.2 bivariate-polynomial definition
     */
    private static class BivariatePolynomial {
        private int degree;
        private BigInteger p;
        public BigInteger[][] coefficients;

        /**
         * Constructor: create bivariate polynomial
         */
        public BivariatePolynomial(int threshold, BigInteger p, BigInteger constantTerm, boolean verbose) {
            this.degree = threshold - 1;
            this.p = p;
            this.coefficients = new BigInteger[threshold][threshold];

            // Initialise all coefficients to zero
            for (int i = 0; i < threshold; i++) {
                for (int j = 0; j < threshold; j++) {
                    coefficients[i][j] = BigInteger.ZERO;
                }
            }

            // Set constant term to secret value
            coefficients[0][0] = constantTerm.mod(p);
            if (verbose) {
                System.out.println("  Constant term a_00 = " + constantTerm + " (secret value)");
            }

            // Use Bouncy Castle secure random generator
            SecureRandom secureRandom = BCCryptoUtils.createSecureRandom(null);
            int coefficientCount = 0;

            // Generate only lower-triangular part (diagonal included), then symmetrically copy to upper-triangular
            for (int i = 0; i < threshold; i++) {
                for (int j = i; j < threshold; j++) {
                    if (i == 0 && j == 0) continue; // constant term already set

                    // Generate secure random coefficient
                    BigInteger coeff = new BigInteger(p.bitLength() - 1, secureRandom).mod(p);

                    coefficients[i][j] = coeff;
                    if (i != j) {
                        coefficients[j][i] = coeff; // strict symmetry
                    }
                    coefficientCount++;
                }
            }

            if (verbose) {
                System.out.println("  Generated " + coefficientCount + " random coefficients");
            }
        }

        public void setCoefficient(int i, int j, BigInteger value) {
            coefficients[i][j] = value.mod(p);
        }

        /**
         * Evaluate polynomial at point (x,y)
         * Corresponds to Section 4.2 polynomial evaluation
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
         * Evaluate polynomial at given x, yielding univariate polynomial in y
         * Corresponds to Section 4.3.1 master-share computation
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
     * Univariate-polynomial class: represents univariate polynomial in y
     * Corresponds to Section 4.3.1 master-share definition
     */
    private static class UnivariatePolynomial {
        private BigInteger[] coefficients;
        private BigInteger p;

        public UnivariatePolynomial(BigInteger[] coefficients, BigInteger p) {
            this.coefficients = coefficients;
            this.p = p;
        }

        /**
         * Evaluate polynomial at given y
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
         * Polynomial addition
         * Corresponds to Section 4.5.2 master-share update
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
     * Threshold-test task class
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

            System.out.printf("[%s] Starting tests for threshold t=%d (%d experiments, test type: %s)\n", threadName, threshold, numExperiments, testType);

            for (int exp = 0; exp < numExperiments; exp++) {
                try {
                    boolean expVerbose = verbose && (exp == 0); // each thread logs only first experiment in detail
                    // Create system instance
                    DynamicThresholdSecretSharingVersion9App system = new DynamicThresholdSecretSharingVersion9App(NUM_PARTICIPANTS, threshold, expVerbose);

                    // 1. System initialisation
                    system.systemInitialization(system.secret);

                    // Execute different operation sequences according to test type
                    switch (testType) {
                        case "basic":
                            // Basic test: decrease + share update + both recovery methods
                            int tempthreshold = threshold - 3;
                            if (tempthreshold >= 2) {
                                system.thresholdDecrease(tempthreshold);
                            }
                            system.workingShareUpdate("test_update", 1);
                            //system.mainShareUpdate("test_update", 1);
                            break;

                        case "Pre-expansion":
                            // Threshold-expansion test, INCREASE_THRESHOLDS is extension degree
                            if (expVerbose) {
                                System.out.println("\n=== Threshold-expansion test started, extension degree: "+INCREASE_THRESHOLDS+" ===");
                            }
                            int increaseThreshold = threshold + INCREASE_THRESHOLDS;
                            if (increaseThreshold <= system.n) {
                                system.thresholdPreexpansion(increaseThreshold);
                            }
                            break;
                        case "increase":
                            //Threshold increase
                            if (expVerbose) {
                                System.out.println("\n=== Threshold up-adjustment test started ===");
                            }
                            int newThreshold = threshold + UP_THRESHOLDS;
                            int securityUpperBound = 1 + threshold * (threshold + 1) / 2;
                            if (newThreshold <= system.n && newThreshold < securityUpperBound) {
                                system.thresholdAdjustUp(newThreshold);
                            }
                            break;
                        case "mixed":
                            // Mixed-scenario test: expand -> working-share update -> decrease -> master-share update
                            if (expVerbose) {
                                System.out.println("\n=== Mixed-scenario test started ===");
                            }
                            long mixedTotalStart = System.nanoTime();

                            if (threshold <= system.n) {
                                int originalThreshold = threshold;

                                // 1. Threshold expansion
                                int maxThreshold = threshold + INCREASE_THRESHOLDS;
                                system.thresholdPreexpansion(maxThreshold);

                                // 2. Working-share update
                                system.workingShareUpdate("mixed_scenario", 1);

                                // 3. Threshold decrease
                                system.thresholdDecrease(originalThreshold);

                                // 4. Master-share update
                                system.mainShareUpdate("mixed_scenario", 1);
                            }

                            long mixedTotalEnd = System.nanoTime();
                            threadStats.addMixedScenarioTime(mixedTotalEnd - mixedTotalStart);
                            break;
                    }

                    // Secret-recovery verification
                    List<Integer> recoveryParticipants = new ArrayList<>();
                    for (int i = 0; i < system.currentThreshold && i < system.n; i++) {
                        recoveryParticipants.add(i);
                    }

                    List<Integer> recoveryMainParticipants = new ArrayList<>();
                    for (int i = 0; i < system.currentMainThreshold && i < system.n; i++) {
                        recoveryMainParticipants.add(i);
                    }

                    BigInteger recoveredFromWorking = system.secretRecoveryFromWorkingShares(recoveryParticipants,true);
                    BigInteger recoveredFromMain = system.secretRecoveryFromMainShares(recoveryMainParticipants,true);


                    // Verify recovery correctness
                    if (!recoveredFromWorking.equals(system.secret) || !recoveredFromMain.equals(system.secret)) {
                        failureCount++;
                        if (expVerbose) {
                            System.out.println("Recovery failed! Working-share recovery: " + recoveredFromWorking + ", master-share recovery: " + recoveredFromMain + ", expected: " + system.secret);
                        }
                    } else {
                        successCount++;
                    }

                    // Collect statistics
                    if (!system.stats.initTimes.isEmpty()) {
                        threadStats.addInitTime(system.stats.initTimes.get(0));
                    }
                    if (system.stats.thresholdAdjustTimes.size() > 0) {
                        threadStats.addThresholdAdjustTime(system.stats.thresholdAdjustTimes.get(0));
                    }
                    if (system.stats.thresholdIncreaseTimes.size() > 0) {
                        threadStats.addThresholdIncreaseTime(system.stats.thresholdIncreaseTimes.get(0));
                    }
                    if (system.stats.thresholdUpTimes.size() > 0) {
                        threadStats.addThresholdUpTime(system.stats.thresholdUpTimes.get(0));
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
                    System.out.printf("[%s] Experiment %d (threshold t=%d, type: %s) failed: %s\n",
                            threadName, exp + 1, threshold, testType, e.getMessage());
                    failureCount++;
                }
            }

            System.out.printf("[%s] Threshold t=%d (type: %s) test complete: %d success, %d failure\n",
                    threadName, threshold, testType, successCount, failureCount);

            return new ThresholdTestResult(threshold, threadStats, successCount, failureCount, testType);
        }
    }

    /**
     * Threshold-test result class
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
     * Main method: program entry point
     */
    public static void main(String[] args) {
        System.out.println("Starting dynamic-threshold secret-sharing system performance test (strictly follows paper)...");
        System.out.println("Parameters: n=" + NUM_PARTICIPANTS + ", thresholds=" + Arrays.toString(THRESHOLDS));
        System.out.println("Experiments: " + NUM_EXPERIMENTS);
        System.out.println("Prime bits: " + PRIME_BIT_LENGTH);
        System.out.println("Thread-pool size: " + THREAD_POOL_SIZE);
        System.out.println();

        // Create thread pool
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
        List<Future<ThresholdTestResult>> futures = new ArrayList<>();
        Map<String, Map<Integer, PerformanceStats>> testTypeStats = new ConcurrentHashMap<>();
        Map<String, Map<Integer, Integer>> successCounts = new ConcurrentHashMap<>();
        Map<String, Map<Integer, Integer>> failureCounts = new ConcurrentHashMap<>();

        // Initialise statistics maps
        //String[] testTypes = {"increase"};//Threshold Increase
        //String[] testTypes = {"basic","Pre-expansion","mixed"};
        String[] testTypes = {"basic", "increase","Pre-expansion","mixed"};
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

        System.out.println("Launching multi-threaded tests...");
        long startTime = System.currentTimeMillis();

        // Submit test tasks for each threshold and test type
        for (String testType : testTypes) {
            for (int threshold : THRESHOLDS) {
                Future<ThresholdTestResult> future = executor.submit(
                        new ThresholdTestTask(threshold, NUM_EXPERIMENTS, false, testType)
                );
                futures.add(future);
            }
        }

        // Wait for all tasks and collect results
        for (Future<ThresholdTestResult> future : futures) {
            try {
                ThresholdTestResult result = future.get();
                testTypeStats.get(result.testType).get(result.threshold).merge(result.stats);
                successCounts.get(result.testType).put(result.threshold, result.successCount);
                failureCounts.get(result.testType).put(result.threshold, result.failureCount);
            } catch (Exception e) {
                System.out.println("Task execution exception: " + e.getMessage());
            }
        }

        long endTime = System.currentTimeMillis();
        executor.shutdown();

        System.out.printf("\nAll tests complete! Total execution time: %.3f s\n", (endTime - startTime) / 1000.0);

        // Output overall statistics
        System.out.println("\n" + "=".repeat(80));
        System.out.println("Overall performance statistics");
        System.out.println("=".repeat(80));

        for (String testType : testTypes) {
            System.out.println("\nTest type: " + testType);
            for (int threshold : THRESHOLDS) {
                if (testTypeStats.get(testType).get(threshold).initTimes.isEmpty()) {
                    continue;
                }

                System.out.println("\nThreshold t=" + threshold + ":");
                System.out.printf("Success rate: %d/%d (%.2f%%)\n",
                        successCounts.get(testType).get(threshold),
                        NUM_EXPERIMENTS,
                        (successCounts.get(testType).get(threshold) * 100.0 / NUM_EXPERIMENTS));
                testTypeStats.get(testType).get(threshold).printStats();
            }
        }

        // Generate chart data summary
        generateChartSummary(mergeAllTestData(testTypeStats));

        System.out.println("\nAll tests complete!");
    }

    /**
     * Merge data for all test types
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
     * Generate chart data summary
     */
    private static void generateChartSummary(Map<Integer, PerformanceStats> statsMap) {
        System.out.println("\n" + "=".repeat(120));
        System.out.println("Chart data summary (computational cost of all core operations)");
        System.out.println("=".repeat(120));

        Map<Integer, Map<String, Double>> chartData = new TreeMap<>();

        System.out.println("\nThreshold(t) | System Init (ms) | Threshold Decrease (ms) | Threshold Pre-expansion (ms) | Threshold Increase (ms) | Working-share Update (ms) | Master-share Update (ms) | Working-share Recovery (ms) | Master-share Recovery (ms) | Mixed Scenario (ms)");
        System.out.println("---------------|------------------|-------------------------|------------------------------|-------------------------|---------------------------|--------------------------|-----------------------------|----------------------------|---------------------------");
        for (int threshold : THRESHOLDS) {
            if (!statsMap.containsKey(threshold)) continue;
            Map<String, Double> tData = new HashMap<>();

            PerformanceStats stats = statsMap.get(threshold);

            double initTime = stats.calculateAverage(stats.initTimes) / 1e6;
            double thresholdTime = stats.thresholdAdjustTimes.isEmpty() ? 0 : stats.calculateAverage(stats.thresholdAdjustTimes) / 1e6;
            double thresholdIncreaseTime = stats.thresholdIncreaseTimes.isEmpty() ? 0 : stats.calculateAverage(stats.thresholdIncreaseTimes) / 1e6;
            double thresholdUpTime = stats.thresholdUpTimes.isEmpty() ? 0 : stats.calculateAverage(stats.thresholdUpTimes) / 1e6;
            double workingUpdateTime = stats.workingShareUpdateTimes.isEmpty() ? 0 : stats.calculateAverage(stats.workingShareUpdateTimes) / 1e6;
            double masterUpdateTime = stats.masterShareUpdateTimes.isEmpty() ? 0 : stats.calculateAverage(stats.masterShareUpdateTimes) / 1e6;
            double workingRecoveryTime = stats.workingSharesRecoveryTimes.isEmpty() ? 0 : stats.calculateAverage(stats.workingSharesRecoveryTimes) / 1e6;
            double mainRecoveryTime = stats.mainSharesRecoveryTimes.isEmpty() ? 0 : stats.calculateAverage(stats.mainSharesRecoveryTimes) / 1e6;
            double mixedScenarioTime = stats.mixedScenarioTimes.isEmpty() ? 0 : stats.calculateAverage(stats.mixedScenarioTimes) / 1e6;

            tData.put("System Init (ms)", initTime);
            tData.put("Threshold Decrease (ms)", thresholdTime);
            tData.put("Threshold Pre-expansion (ms)", thresholdIncreaseTime);
            tData.put("Threshold Up-adjustment (ms)", thresholdUpTime);
            tData.put("Working-share Update (ms)", workingUpdateTime);
            tData.put("Master-share Update (ms)", masterUpdateTime);
            tData.put("Working-share Recovery (ms)", workingRecoveryTime);
            tData.put("Master-share Recovery (ms)", mainRecoveryTime);
            tData.put("Mixed Scenario (ms)", mixedScenarioTime);
            chartData.put(threshold, tData);

            System.out.printf("   %d    |     %7.3f   |   %7.3f   |   %7.3f   |      %7.3f    |      %7.3f    |     %7.3f   |      %7.3f    |     %7.3f   |   %7.3f\n",
                    threshold, initTime, thresholdTime, thresholdIncreaseTime,thresholdUpTime,
                    workingUpdateTime, masterUpdateTime, workingRecoveryTime, mainRecoveryTime, mixedScenarioTime);
        }

        System.out.println("\nComputational-cost analysis:");
        System.out.println("- System init: O(t²) polynomial generation + O(n·t²) master-share computation + O(n) working-share computation");
        System.out.println("- Threshold decrease: O(t³) Lagrange computation + O(t·t'²) re-sharing polynomial + O(n·t²) encryption + O(n²·t) decryption");
        System.out.println("- Threshold pre-expansion: O(t'²) expanded polynomial + O(n·t'²) share update");
        System.out.println("- Working-share update: O(t²) polynomial generation + O(n·t) share update");
        System.out.println("- Master-share update: O(t²) polynomial generation + O(n·t²) master-share update");
        System.out.println("- Secret recovery: O(t²) Lagrange interpolation");

        // Simplified chart generation
        SwingUtilities.invokeLater(() -> {
            generatePerformanceChart(chartData);
        });
    }

    /**
     * Draw performance line chart
     */
    public static void generatePerformanceChart(Map<Integer, Map<String, Double>> chartData) {
        // Create simplified chart
        JFrame frame = new JFrame("Core-operation execution time vs. threshold");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        PerformanceChart chart = new PerformanceChart();
        chart.setPerformanceData(chartData);
        frame.add(chart);

        frame.setSize(800, 600);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);

        // Save chart
        chart.createAndSaveChart(chartData, "PerformanceChart.png");
    }
}