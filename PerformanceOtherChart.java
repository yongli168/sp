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
 * 性能图表类：用于可视化展示动态阈值秘密共享系统的性能数据
 * 支持绘制折线图、柱状图等多种图表类型
 */
public class PerformanceOtherChart extends JPanel {
    private Map<Integer, Map<String, Double>> performanceData;
    // 扩展颜色数组以支持更多操作
    private Color[] colors = {Color.BLUE, Color.RED, Color.GREEN, Color.ORANGE, Color.DARK_GRAY, Color.YELLOW};
    // 扩展操作列表
    private String[] operations = {
            "文献[2]", "文献[3]","文献[4]", "文献[8]", "文献[12]", "本方案"
    };

    /**
     * 默认构造函数
     */
    public PerformanceOtherChart() {
        // 初始化数据结构
        performanceData = new TreeMap<>();
        // 正确初始化每个阈值的数据
        initializeData();
        setPreferredSize(new Dimension(800, 600));
        setBackground(Color.WHITE);
    }

    /**
     * 带数据参数的构造函数
     * @param data 性能数据
     */
    public PerformanceOtherChart(Map<Integer, Map<String, Double>> data) {
        this.performanceData = new TreeMap<>(data);
        setPreferredSize(new Dimension(1000, 700));
        setBackground(Color.WHITE);
    }

    /**
     * 初始化示例数据（用于测试）
     */
    private void initializeData() {
        // 阈值5的数据
        Map<String, Double> t5Data = new HashMap<>();
        t5Data.put("文献[2]", 0.289);
        t5Data.put("文献[3]", 0.1);
        t5Data.put("文献[4]", 0.592);
        t5Data.put("文献[5]", 6.592);
        t5Data.put("文献[12]", 3.675);
        t5Data.put("本方案", 0.473);
        performanceData.put(5, t5Data);

        // 阈值7的数据
        Map<String, Double> t7Data = new HashMap<>();
        t7Data.put("文献[2]", 0.424);
        t7Data.put("文献[3]", 0.153);
        t7Data.put("文献[4]", 0.621);
        t7Data.put("文献[5]", 6.328);
        t7Data.put("文献[12]", 2.887);
        t7Data.put("本方案", 0.568);
        performanceData.put(7, t7Data);

        // 阈值9的数据
        Map<String, Double> t9Data = new HashMap<>();
        t9Data.put("文献[2]", 0.636);
        t9Data.put("文献[3]", 0.245);
        t9Data.put("文献[4]", 0.4);
        t9Data.put("文献[5]", 5.683);
        t9Data.put("文献[12]", 2.917);
        t9Data.put("本方案", 0.657);
        performanceData.put(9, t9Data);

        // 阈值11的数据
        Map<String, Double> t11Data = new HashMap<>();
        t11Data.put("文献[2]", 0.861);
        t11Data.put("文献[3]", 0.369);
        t11Data.put("文献[4]", 0.433);
        t11Data.put("文献[5]", 5.251);
        t11Data.put("文献[12]", 2.088);
        t11Data.put("本方案", 0.746);
        performanceData.put(11, t11Data);

        // 阈值13的数据
        Map<String, Double> t13Data = new HashMap<>();
        t13Data.put("文献[2]", 1.435);
        t13Data.put("文献[3]", 0.534);
        t13Data.put("文献[4]", 0.284);
        t13Data.put("文献[5]", 4.559);
        t13Data.put("文献[12]", 3.065);
        t13Data.put("本方案", 0.844);
        performanceData.put(13, t13Data);
    }

    /**
     * 绘制组件
     * @param g 图形上下文
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
     * 绘制图表标题
     * @param g2 图形上下文
     */
    private void drawTitle(Graphics2D g2) {
        g2.setColor(Color.BLACK);
        g2.setFont(new Font("宋体", Font.BOLD, 16));

        // 根据数据内容动态生成标题
        String title = "动态阈值秘密共享系统性能分析";
        if (performanceData != null && !performanceData.isEmpty()) {
            boolean hasPrecompute = performanceData.values().stream()
                    .anyMatch(data -> data.containsKey("预计算时间(ms)") && data.get("预计算时间(ms)") > 0);

            if (hasPrecompute) {
                title = "包含预计算的系统性能分析";
            }
        }

        int titleWidth = g2.getFontMetrics().stringWidth(title);
        g2.drawString(title, (getWidth() - titleWidth) / 2, 30);

        // 英文标题
        g2.setFont(new Font("Arial", Font.PLAIN, 12));
        String englishTitle = "Performance Analysis of Dynamic Threshold Secret Sharing System";
        int englishTitleWidth = g2.getFontMetrics().stringWidth(englishTitle);
        g2.drawString(englishTitle, (getWidth() - englishTitleWidth) / 2, 50);
    }

    /**
     * 绘制主图表
     * @param g2 图形上下文
     */
    private void drawChart(Graphics2D g2) {
        int padding = 80;
        int chartWidth = getWidth() - 2 * padding;
        int chartHeight = getHeight() - 2 * padding - 50; // 为标题留出空间

        // 绘制坐标轴
        g2.setColor(Color.BLACK);
        g2.setStroke(new BasicStroke(2));
        g2.drawLine(padding, padding, padding, padding + chartHeight); // Y轴
        g2.drawLine(padding, padding + chartHeight, padding + chartWidth, padding + chartHeight); // X轴

        // 绘制箭头
        drawArrow(g2, padding, padding, true); // Y轴箭头
        drawArrow(g2, padding + chartWidth, padding + chartHeight, false); // X轴箭头

        // 绘制刻度和标签
        drawAxesLabels(g2, padding, chartWidth, chartHeight);

        // 绘制数据线
        drawDataLines(g2, padding, chartWidth, chartHeight);
    }

    /**
     * 绘制坐标轴箭头
     * @param g2 图形上下文
     * @param x 箭头x坐标
     * @param y 箭头y坐标
     * @param isVertical 是否为垂直箭头
     */
    private void drawArrow(Graphics2D g2, int x, int y, boolean isVertical) {
        int arrowSize = 8;
        if (isVertical) {
            // Y轴箭头（向上）
            g2.drawLine(x, y, x - arrowSize/2, y + arrowSize);
            g2.drawLine(x, y, x + arrowSize/2, y + arrowSize);
        } else {
            // X轴箭头（向右）
            g2.drawLine(x, y, x - arrowSize, y - arrowSize/2);
            g2.drawLine(x, y, x - arrowSize, y + arrowSize/2);
        }
    }

    /**
     * 绘制坐标轴标签和刻度
     * @param g2 图形上下文
     * @param padding 内边距
     * @param chartWidth 图表宽度
     * @param chartHeight 图表高度
     */
    private void drawAxesLabels(Graphics2D g2, int padding, int chartWidth, int chartHeight) {
        // X轴标签 - 阈值
        Integer[] thresholds = performanceData.keySet().toArray(new Integer[0]);
        int xStep = chartWidth / (thresholds.length + 1);

        g2.setFont(new Font("宋体", Font.PLAIN, 12));
        for (int i = 0; i < thresholds.length; i++) {
            int x = padding + (i + 1) * xStep;
            g2.drawString("t=" + thresholds[i], x - 10, padding + chartHeight + 20);

            // 绘制X轴刻度
            g2.drawLine(x, padding + chartHeight, x, padding + chartHeight + 5);
        }

        // X轴标题
        g2.setFont(new Font("宋体", Font.BOLD, 14));
        String xLabel = "阈值 t (Threshold t)";
        int xLabelWidth = g2.getFontMetrics().stringWidth(xLabel);
        g2.drawString(xLabel, padding + chartWidth/2 - xLabelWidth/2, padding + chartHeight + 40);

        // Y轴标签 - 执行时间
        double maxTime = getMaxExecutionTime();
        int ySteps = 6;
        double timeStep = maxTime / ySteps;

        g2.setFont(new Font("宋体", Font.PLAIN, 12));
        for (int i = 0; i <= ySteps; i++) {
            int y = padding + chartHeight - (int)((i * timeStep) / maxTime * chartHeight);
            String label = String.format("%.1f", i * timeStep);
            g2.drawString(label, padding - 30, y + 5);

            // 绘制Y轴刻度
            g2.drawLine(padding, y, padding - 5, y);

            // 绘制网格线
            g2.setColor(Color.LIGHT_GRAY);
            g2.setStroke(new BasicStroke(1));
            g2.drawLine(padding, y, padding + chartWidth, y);
            g2.setColor(Color.BLACK);
            g2.setStroke(new BasicStroke(2));
        }

        // Y轴标题
        g2.setFont(new Font("宋体", Font.BOLD, 14));
        String yLabel = "执行时间 (Execution Time / ms)";
        // 垂直绘制Y轴标签
        FontMetrics fm = g2.getFontMetrics();
        int yLabelWidth = fm.stringWidth(yLabel);
        AffineTransform originalTransform = g2.getTransform();
        g2.rotate(-Math.PI/2, 20, padding + chartHeight/2 + yLabelWidth/2);
        g2.drawString(yLabel, 20, padding + chartHeight/2 + yLabelWidth/2);
        g2.setTransform(originalTransform);
    }

    /**
     * 绘制数据线
     * @param g2 图形上下文
     * @param padding 内边距
     * @param chartWidth 图表宽度
     * @param chartHeight 图表高度
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
                // 添加空值检查
                Map<String, Double> thresholdData = performanceData.get(threshold);
                if (thresholdData == null) continue;

                Double time = thresholdData.get(operation);
                if (time == null) continue;

                int x = padding + (i + 1) * xStep;
                int y = padding + chartHeight - (int)((time / maxTime) * chartHeight);
                points.add(new Point(x, y));

                // 绘制数据点
                g2.fillOval(x - 4, y - 4, 8, 8);

                // 在数据点旁边显示具体数值
                g2.setColor(Color.BLACK);
                g2.setFont(new Font("Arial", Font.PLAIN, 10));
                String valueLabel = String.format("%.3f", time);
                g2.drawString(valueLabel, x - 10, y - 10);
                g2.setColor(colors[opIndex]);
            }

            // 绘制连线
            for (int i = 0; i < points.size() - 1; i++) {
                Point p1 = points.get(i);
                Point p2 = points.get(i + 1);
                g2.drawLine(p1.x, p1.y, p2.x, p2.y);
            }
        }
    }

    /**
     * 绘制图例
     * @param g2 图形上下文
     */
    private void drawLegend(Graphics2D g2) {
        int legendX = getWidth() - 200;
        int legendY = 80;

        g2.setColor(Color.BLACK);
        g2.setFont(new Font("宋体", Font.BOLD, 14));
        g2.drawString("图例 (Legend)", legendX, legendY - 10);

        // 绘制图例背景
        g2.setColor(new Color(255, 255, 255, 200));
        g2.fillRect(legendX - 10, legendY, 180, operations.length * 25 + 10);
        g2.setColor(Color.GRAY);
        g2.drawRect(legendX - 10, legendY, 180, operations.length * 25 + 10);

        g2.setFont(new Font("宋体", Font.PLAIN, 12));
        for (int i = 0; i < operations.length; i++) {
            g2.setColor(colors[i]);
            g2.fillRect(legendX, legendY + i * 25 + 10, 15, 15);
            g2.setColor(Color.BLACK);
            g2.drawString(operations[i], legendX + 20, legendY + i * 25 + 22);
        }
    }

    /**
     * 获取最大执行时间（用于Y轴缩放）
     * @return 最大执行时间
     */
    private double getMaxExecutionTime() {
        double max = 0;
        for (Map<String, Double> data : performanceData.values()) {
            if (data == null) continue;
            for (double time : data.values()) {
                if (time > max) max = time;
            }
        }
        return max * 1.1; // 增加10%的余量
    }

    /**
     * 更新性能数据
     * @param threshold 阈值
     * @param operation 操作名称
     * @param time 执行时间
     */
    public void updatePerformanceData(int threshold, String operation, double time) {
        if (!performanceData.containsKey(threshold)) {
            performanceData.put(threshold, new HashMap<>());
        }
        performanceData.get(threshold).put(operation, time);
        repaint();
    }

    /**
     * 设置真实性能数据
     * @param data 性能数据
     */
    public void setPerformanceData(Map<Integer, Map<String, Double>> data) {
        this.performanceData = new TreeMap<>();
        for (Map.Entry<Integer, Map<String, Double>> entry : data.entrySet()) {
            this.performanceData.put(entry.getKey(), new HashMap<>(entry.getValue()));
        }
        repaint();
    }

    /**
     * 保存图表为PNG文件
     * @param filename 文件名
     */
    public void saveChartAsImage(String filename) {
        // 创建与面板相同尺寸的缓冲图像
        BufferedImage image = new BufferedImage(getWidth(), getHeight(), BufferedImage.TYPE_INT_RGB);
        Graphics2D g2 = image.createGraphics();

        // 设置背景为白色
        g2.setColor(Color.WHITE);
        g2.fillRect(0, 0, getWidth(), getHeight());

        // 将面板内容绘制到图像上
        paint(g2);

        try {
            // 保存为PNG文件
            File file = new File(filename);
            ImageIO.write(image, "PNG", file);
            System.out.println("图表已保存为: " + file.getAbsolutePath());
        } catch (IOException e) {
            System.err.println("保存图表时出错: " + e.getMessage());
        } finally {
            g2.dispose();
        }
    }

    /**
     * 创建并保存图表
     * @param performanceData 性能数据
     * @param filename 文件名
     */
    public void createAndSaveChart(Map<Integer, Map<String, Double>> performanceData, String filename) {
        PerformanceOtherChart chart = new PerformanceOtherChart(performanceData);
        chart.setPreferredSize(new Dimension(1000, 700));

        // 创建临时框架以确保正确渲染
        JFrame tempFrame = new JFrame();
        tempFrame.add(chart);
        tempFrame.pack();
        tempFrame.setVisible(true);

        // 延迟保存以确保渲染完成
        Timer timer = new Timer(500, e -> {
            chart.saveChartAsImage(filename);
            tempFrame.dispose();
        });
        timer.setRepeats(false);
        timer.start();
    }

    /**
     * 主方法：测试图表功能
     * @param args 命令行参数
     */
    public static void main(String[] args) {
        // 使用SwingUtilities确保在事件分发线程中运行
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("动态阈值秘密共享系统性能图表");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

            PerformanceOtherChart chart = new PerformanceOtherChart();
            frame.add(chart);

            frame.pack();
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);
        });
    }
}