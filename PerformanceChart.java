package code;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.Timer;
import java.awt.*;
import java.awt.geom.AffineTransform;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.List;

/**
 * Performance-chart component: visualises performance data for the dynamic-threshold secret-sharing system
 * Supports line charts, bar charts and other plot types
 */
public class PerformanceChart extends JPanel {
    private Map<Integer, Map<String, Double>> performanceData;
    // Extended colour palette for additional operations
    private Color[] colors = {Color.BLUE, Color.RED, Color.GREEN, Color.ORANGE, Color.DARK_GRAY,
            Color.MAGENTA, Color.CYAN, Color.GRAY, Color.YELLOW};
    // Extended operation list
    private String[] operations = {
            "System Init (ms)", "Threshold Decrease (ms)", "Threshold Expansion (ms)", "Threshold Increase (ms)",
            "Working-Share Update (ms)", "Master-Share Update (ms)","Working-Share Recovery (ms)", "Master-Share Recovery (ms)", "Mixed Scenario (ms)"
    };

    /**
     * Default constructor
     */
    public PerformanceChart() {
        // Initialise data structures
        performanceData = new TreeMap<>();
        // Properly initialise data for each threshold
        initializeData();
        setPreferredSize(new Dimension(800, 600));
        setBackground(Color.WHITE);
    }

    /**
     * Constructor with data parameter
     * @param data performance data
     */
    public PerformanceChart(Map<Integer, Map<String, Double>> data) {
        this.performanceData = new TreeMap<>(data);
        setPreferredSize(new Dimension(1000, 700));
        setBackground(Color.WHITE);
    }

    /**
     * Initialise sample data (for testing)
     */
    private void initializeData() {
        // Threshold t = 4
        Map<String, Double> t4Data = new HashMap<>();
        t4Data.put("System Init (ms)", 12.3);
        t4Data.put("Threshold Decrease (ms)", 45.7);
        t4Data.put("Threshold Increase (ms)", 38.2);
        t4Data.put("Working-Share Update (ms)", 8.9);
        t4Data.put("Master-Share Update (ms)", 10.1);
        t4Data.put("Secret Recovery (ms)", 5.4);
        performanceData.put(4, t4Data);

        // Threshold t = 5
        Map<String, Double> t5Data = new HashMap<>();
        t5Data.put("System Init (ms)", 15.2);
        t5Data.put("Threshold Decrease (ms)", 50.5);
        t5Data.put("Threshold Increase (ms)", 42.8);
        t5Data.put("Working-Share Update (ms)", 9.9);
        t5Data.put("Master-Share Update (ms)", 11.3);
        t5Data.put("Secret Recovery (ms)", 6.1);
        performanceData.put(5, t5Data);

        // Threshold t = 6
        Map<String, Double> t6Data = new HashMap<>();
        t6Data.put("System Init (ms)", 18.6);
        t6Data.put("Threshold Decrease (ms)", 55.8);
        t6Data.put("Threshold Increase (ms)", 47.5);
        t6Data.put("Working-Share Update (ms)", 10.5);
        t5Data.put("Master-Share Update (ms)", 12.7);
        t6Data.put("Secret Recovery (ms)", 6.8);
        performanceData.put(6, t6Data);
    }

    /**
     * Paint component
     * @param g graphics context
     */
    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        Graphics2D g2 = (Graphics2D) g;
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        drawTitle(g2);
        drawChart(g2);
        drawLegend(g2);
    }

    /**
     * Draw chart title
     * @param g2 graphics context
     */
    private void drawTitle(Graphics2D g2) {
        g2.setColor(Color.BLACK);
        g2.setFont(new Font("SimSun", Font.BOLD, 16));

        // Generate title dynamically based on data content
        String title = "Dynamic-Threshold Secret-Sharing System Performance Analysis";
        if (performanceData != null && !performanceData.isEmpty()) {
            boolean hasPrecompute = performanceData.values().stream()
                    .anyMatch(data -> data.containsKey("Precompute Time (ms)") && data.get("Precompute Time (ms)") > 0);

            if (hasPrecompute) {
                title = "System Performance Analysis with Pre-computation";
            }
        }

        int titleWidth = g2.getFontMetrics().stringWidth(title);
        g2.drawString(title, (getWidth() - titleWidth) / 2, 30);

        // English title
        g2.setFont(new Font("Arial", Font.PLAIN, 12));
        String englishTitle = "Performance Analysis of Dynamic Threshold Secret Sharing System";
        int englishTitleWidth = g2.getFontMetrics().stringWidth(englishTitle);
        g2.drawString(englishTitle, (getWidth() - englishTitleWidth) / 2, 50);
    }

    /**
     * Draw main chart
     * @param g2 graphics context
     */
    private void drawChart(Graphics2D g2) {
        int padding = 80;
        int chartWidth = getWidth() - 2 * padding;
        int chartHeight = getHeight() - 2 * padding - 50; // reserve space for title

        // Draw axes
        g2.setColor(Color.BLACK);
        g2.setStroke(new BasicStroke(2));
        g2.drawLine(padding, padding, padding, padding + chartHeight); // Y-axis
        g2.drawLine(padding, padding + chartHeight, padding + chartWidth, padding + chartHeight); // X-axis

        // Draw arrows
        drawArrow(g2, padding, padding, true); // Y-axis arrow
        drawArrow(g2, padding + chartWidth, padding + chartHeight, false); // X-axis arrow

        // Draw ticks and labels
        drawAxesLabels(g2, padding, chartWidth, chartHeight);

        // Draw data lines
        drawDataLines(g2, padding, chartWidth, chartHeight);
    }

    /**
     * Draw axis arrows
     * @param g2 graphics context
     * @param x arrow x-coordinate
     * @param y arrow y-coordinate
     * @param isVertical vertical arrow flag
     */
    private void drawArrow(Graphics2D g2, int x, int y, boolean isVertical) {
        int arrowSize = 8;
        if (isVertical) {
            // Y-axis arrow (upward)
            g2.drawLine(x, y, x - arrowSize/2, y + arrowSize);
            g2.drawLine(x, y, x + arrowSize/2, y + arrowSize);
        } else {
            // X-axis arrow (rightward)
            g2.drawLine(x, y, x - arrowSize, y - arrowSize/2);
            g2.drawLine(x, y, x - arrowSize, y + arrowSize/2);
        }
    }

    /**
     * Draw axis labels and ticks
     * @param g2 graphics context
     * @param padding padding
     * @param chartWidth chart width
     * @param chartHeight chart height
     */
    private void drawAxesLabels(Graphics2D g2, int padding, int chartWidth, int chartHeight) {
        // X-axis labels – threshold
        Integer[] thresholds = performanceData.keySet().toArray(new Integer[0]);
        int xStep = chartWidth / (thresholds.length + 1);

        g2.setFont(new Font("SimSun", Font.PLAIN, 12));
        for (int i = 0; i < thresholds.length; i++) {
            int x = padding + (i + 1) * xStep;
            g2.drawString("t=" + thresholds[i], x - 10, padding + chartHeight + 20);

            // Draw X-axis tick
            g2.drawLine(x, padding + chartHeight, x, padding + chartHeight + 5);
        }

        // X-axis title
        g2.setFont(new Font("SimSun", Font.BOLD, 14));
        String xLabel = "Threshold t (Threshold t)";
        int xLabelWidth = g2.getFontMetrics().stringWidth(xLabel);
        g2.drawString(xLabel, padding + chartWidth/2 - xLabelWidth/2, padding + chartHeight + 40);

        // Y-axis labels – execution time
        double maxTime = getMaxExecutionTime();
        int ySteps = 6;
        double timeStep = maxTime / ySteps;

        g2.setFont(new Font("SimSun", Font.PLAIN, 12));
        for (int i = 0; i <= ySteps; i++) {
            int y = padding + chartHeight - (int)((i * timeStep) / maxTime * chartHeight);
            String label = String.format("%.1f", i * timeStep);
            g2.drawString(label, padding - 30, y + 5);

            // Draw Y-axis tick
            g2.drawLine(padding, y, padding - 5, y);

            // Draw grid line
            g2.setColor(Color.LIGHT_GRAY);
            g2.setStroke(new BasicStroke(1));
            g2.drawLine(padding, y, padding + chartWidth, y);
            g2.setColor(Color.BLACK);
            g2.setStroke(new BasicStroke(2));
        }

        // Y-axis title
        g2.setFont(new Font("SimSun", Font.BOLD, 14));
        String yLabel = "Execution Time (Execution Time / ms)";
        // Draw Y-axis label vertically
        FontMetrics fm = g2.getFontMetrics();
        int yLabelWidth = fm.stringWidth(yLabel);
        AffineTransform originalTransform = g2.getTransform();
        g2.rotate(-Math.PI/2, 20, padding + chartHeight/2 + yLabelWidth/2);
        g2.drawString(yLabel, 20, padding + chartHeight/2 + yLabelWidth/2);
        g2.setTransform(originalTransform);
    }

    /**
     * Draw data lines
     * @param g2 graphics context
     * @param padding padding
     * @param chartWidth chart width
     * @param chartHeight chart height
     */
    private void drawDataLines(Graphics2D g2, int padding, int chartWidth, int chartHeight) {
        Integer[] thresholds = performanceData.keySet().toArray(new Integer[0]);
        int xStep = chartWidth / (thresholds.length + 1);
        double maxTime = getMaxExecutionTime();

        for (int opIndex = 0; opIndex < operations.length; opIndex++) {
            String operation = operations[opIndex];
            g2.setColor(colors[opIndex]);
            g2.setStroke(new BasicStroke(2.5f));

            List<Point> points = new ArrayList<>();
            for (int i = 0; i < thresholds.length; i++) {
                int threshold = thresholds[i];
                // null check
                Map<String, Double> thresholdData = performanceData.get(threshold);
                if (thresholdData == null) continue;

                Double time = thresholdData.get(operation);
                if (time == null) continue;

                int x = padding + (i + 1) * xStep;
                int y = padding + chartHeight - (int)((time / maxTime) * chartHeight);
                points.add(new Point(x, y));

                // Draw data point
                g2.fillOval(x - 4, y - 4, 8, 8);

                // Display exact value next to the point
                g2.setColor(Color.BLACK);
                g2.setFont(new Font("Arial", Font.PLAIN, 10));
                String valueLabel = String.format("%.3f", time);
                g2.drawString(valueLabel, x - 10, y - 10);
                g2.setColor(colors[opIndex]);
            }

            // Draw connecting lines
            for (int i = 0; i < points.size() - 1; i++) {
                Point p1 = points.get(i);
                Point p2 = points.get(i + 1);
                g2.drawLine(p1.x, p1.y, p2.x, p2.y);
            }
        }
    }

    /**
     * Draw legend
     * @param g2 graphics context
     */
    private void drawLegend(Graphics2D g2) {
        int legendX = getWidth() - 200;
        int legendY = 80;

        g2.setColor(Color.BLACK);
        g2.setFont(new Font("SimSun", Font.BOLD, 14));
        g2.drawString("Legend (Legend)", legendX, legendY - 10);

        // Draw legend background
        g2.setColor(new Color(255, 255, 255, 200));
        g2.fillRect(legendX - 10, legendY, 180, operations.length * 25 + 10);
        g2.setColor(Color.GRAY);
        g2.drawRect(legendX - 10, legendY, 180, operations.length * 25 + 10);

        g2.setFont(new Font("SimSun", Font.PLAIN, 12));
        for (int i = 0; i < operations.length; i++) {
            g2.setColor(colors[i]);
            g2.fillRect(legendX, legendY + i * 25 + 10, 15, 15);
            g2.setColor(Color.BLACK);
            g2.drawString(operations[i], legendX + 20, legendY + i * 25 + 22);
        }
    }

    /**
     * Get maximum execution time (for Y-axis scaling)
     * @return maximum execution time
     */
    private double getMaxExecutionTime() {
        double max = 0;
        for (Map<String, Double> data : performanceData.values()) {
            if (data == null) continue;
            for (double time : data.values()) {
                if (time > max) max = time;
            }
        }
        return max * 1.1; // 10 % margin
    }

    /**
     * Update performance data
     * @param threshold threshold
     * @param operation operation name
     * @param time execution time
     */
    public void updatePerformanceData(int threshold, String operation, double time) {
        if (!performanceData.containsKey(threshold)) {
            performanceData.put(threshold, new HashMap<>());
        }
        performanceData.get(threshold).put(operation, time);
        repaint();
    }

    /**
     * Set actual performance data
     * @param data performance data
     */
    public void setPerformanceData(Map<Integer, Map<String, Double>> data) {
        this.performanceData = new TreeMap<>();
        for (Map.Entry<Integer, Map<String, Double>> entry : data.entrySet()) {
            this.performanceData.put(entry.getKey(), new HashMap<>(entry.getValue()));
        }
        repaint();
    }

    /**
     * Save chart as PNG file
     * @param filename file name
     */
    public void saveChartAsImage(String filename) {
        // Create buffered image with same dimensions as panel
        BufferedImage image = new BufferedImage(getWidth(), getHeight(), BufferedImage.TYPE_INT_RGB);
        Graphics2D g2 = image.createGraphics();

        // Set white background
        g2.setColor(Color.WHITE);
        g2.fillRect(0, 0, getWidth(), getHeight());

        // Paint panel contents onto image
        paint(g2);

        try {
            // Save as PNG
            File file = new File(filename);
            ImageIO.write(image, "PNG", file);
            System.out.println("Chart saved as: " + file.getAbsolutePath());
        } catch (IOException e) {
            System.err.println("Error saving chart: " + e.getMessage());
        } finally {
            g2.dispose();
        }
    }

    /**
     * Create and save chart
     * @param performanceData performance data
     * @param filename file name
     */
    public void createAndSaveChart(Map<Integer, Map<String, Double>> performanceData, String filename) {
        PerformanceChart chart = new PerformanceChart(performanceData);
        chart.setPreferredSize(new Dimension(1000, 700));

        // Create temporary frame to ensure proper rendering
        JFrame tempFrame = new JFrame();
        tempFrame.add(chart);
        tempFrame.pack();
        tempFrame.setVisible(true);

        // Delay save to ensure rendering completion
        Timer timer = new Timer(500, e -> {
            chart.saveChartAsImage(filename);
            tempFrame.dispose();
        });
        timer.setRepeats(false);
        timer.start();
    }

    /**
     * Main method: test chart functionality
     * @param args command-line arguments
     */
    public static void main(String[] args) {
        // Use SwingUtilities to run on Event Dispatch Thread
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("Dynamic-Threshold Secret-Sharing System Performance Chart");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

            PerformanceChart chart = new PerformanceChart();
            frame.add(chart);

            frame.pack();
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);
        });
    }
}