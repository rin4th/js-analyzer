package jsanalyzer.ui;

import burp.api.montoya.MontoyaApi;
import jsanalyzer.model.AjaxFinding;
import jsanalyzer.model.AnalysisResult;
import jsanalyzer.model.DomXssFinding;
import jsanalyzer.model.EndpointFinding;
import jsanalyzer.model.FunctionFinding;
import jsanalyzer.model.SensitiveFinding;
import jsanalyzer.store.JsFile;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.Rectangle2D;
import java.util.ArrayList;
import java.util.List;

/**
 * Right-hand pane: findings tabs for the selected JavaScript file.
 *
 * <p>The tabs and their models are created once and only their contents are
 * updated. Rebuilding a JTabbedPane on every selection can crash Swing's tab
 * painting (BasicTabbedPaneUI throws when the tab count changes during a
 * repaint), which made the Source tab appear blank for large files.</p>
 */
public final class DetailPanel extends JPanel {

    private static final Color HIGHLIGHT = new Color(0x2E, 0x6B, 0xA8, 90);
    /** Above this length a logical line is rendered with visual wrapping. */
    private static final int LONG_LINE_THRESHOLD = 2000;
    /** Prevents multi-megabyte selections when jumping into minified code. */
    private static final int MAX_HIGHLIGHT_CHARS = 500;
    private static final int SOURCE_TAB = 0;
    private static final int ENDPOINTS_TAB = 1;
    private static final int SECRETS_TAB = 2;
    private static final int AJAX_TAB = 3;
    private static final int DOM_TAB = 4;
    private static final int FUNCTIONS_TAB = 5;

    private final MontoyaApi api;
    private final JLabel urlLabel = new JLabel("No file selected");
    private final JLabel metaLabel = new JLabel(" ");
    private final JLabel parseNote = new JLabel();
    private final JTabbedPane tabs = new JTabbedPane(JTabbedPane.TOP);

    private final DefaultTableModel endpointsModel = tableModel(
            "Endpoint", "Type", "Line");
    private final DefaultTableModel secretsModel = tableModel(
            "Keyword", "Value", "Line", "Context");
    private final DefaultTableModel ajaxModel = tableModel(
            "Type", "Method", "URL", "Parameters", "Line");
    private final DefaultTableModel domModel = tableModel(
            "Sink", "Source", "Severity", "Confidence", "Path", "Line");
    private final DefaultTableModel functionsModel = tableModel(
            "Function", "Action", "Signature", "Line");

    private final JTextArea sourceArea = new JTextArea();

    public DetailPanel(MontoyaApi api) {
        super(new BorderLayout(0, 6));
        this.api = api;
        setBorder(BorderFactory.createEmptyBorder(4, 8, 8, 8));

        JPanel header = new JPanel(new BorderLayout(0, 2));
        urlLabel.setFont(displayFont().deriveFont(Font.BOLD, displayFont().getSize2D() + 1f));
        metaLabel.setFont(monoFont().deriveFont(Math.max(10f, monoFont().getSize2D() - 1f)));
        metaLabel.setForeground(new Color(0x80, 0x88, 0x94));
        parseNote.setBorder(BorderFactory.createEmptyBorder(2, 4, 0, 0));
        parseNote.setForeground(new Color(0xB0, 0x8A, 0x30));
        parseNote.setVisible(false);
        header.add(urlLabel, BorderLayout.NORTH);
        header.add(metaLabel, BorderLayout.SOUTH);
        add(header, BorderLayout.NORTH);

        sourceArea.setEditable(false);
        sourceArea.setLineWrap(false);
        sourceArea.setFont(monoFont());
        sourceArea.setTabSize(2);
        tabs.addTab("Source", scroll(sourceArea));
        tabs.addTab("Endpoints", scroll(createTable(endpointsModel,
                new int[]{520, 110, 60}, 2)));
        tabs.addTab("Secrets", scroll(createTable(secretsModel,
                new int[]{90, 480, 60, 220}, 2)));
        tabs.addTab("Ajax / Fetch", scroll(createTable(ajaxModel,
                new int[]{110, 80, 420, 300, 60}, 4)));
        tabs.addTab("DOM XSS", scroll(createTable(domModel,
                new int[]{190, 240, 80, 90, 380, 60}, 5)));
        tabs.addTab("Functions", scroll(createTable(functionsModel,
                new int[]{300, 90, 420, 60}, 3)));

        add(tabs, BorderLayout.CENTER);
        add(parseNote, BorderLayout.SOUTH);
    }

    public void show(JsFile file) {
        sourceArea.getHighlighter().removeAllHighlights();
        parseNote.setVisible(false);
        if (file == null) {
            urlLabel.setText("No file selected");
            urlLabel.setToolTipText(null);
            metaLabel.setText("In-scope JavaScript responses are collected automatically.");
            setSourceText("");
            clearModels();
            setCounts(0, 0, 0, 0, 0);
            return;
        }

        urlLabel.setText(file.url);
        urlLabel.setToolTipText(file.url);
        AnalysisResult result = file.result;
        StringBuilder meta = new StringBuilder();
        meta.append(FilesTableModel.formatSize(file.size))
                .append(" · HTTP ").append(file.statusCode);
        if (file.contentType != null && !file.contentType.isBlank()) {
            meta.append(" · ").append(file.contentType.split(";")[0].trim());
        }
        meta.append(" · seen ").append(file.hits).append(file.hits == 1 ? " time" : " times");

        if (result == null) {
            clearModels();
            setCounts(0, 0, 0, 0, 0);
            String message = "// Analysis " + file.status.toLowerCase() + "…";
            if ("Error".equals(file.status)) {
                message = "// Analysis failed: "
                        + (file.error == null ? "unknown error" : file.error);
            }
            setSourceText(message);
            sourceArea.setCaretPosition(0);
            if ("Error".equals(file.status)) {
                meta.append(" · failed");
            }
            metaLabel.setText(meta.toString());
            return;
        }

        meta.append(" · ").append(result.lineCount).append(" lines · ")
                .append(result.durationMs).append(" ms");
        metaLabel.setText(meta.toString());

        clearModels();
        fillEndpoints(result);
        fillSecrets(result);
        fillAjax(result);
        fillDomXss(result);
        fillFunctions(result);
        setCounts(result.endpoints.size(), result.sensitiveFindings.size(),
                result.ajaxCalls.size(), result.domXssFindings.size(),
                result.interestingFunctions.size());

        setSourceText(file.source == null ? "" : file.source);
        sourceArea.setCaretPosition(0);

        if (result.parseError != null) {
            parseNote.setText("Parser: " + result.parseError + " — results are heuristic.");
            parseNote.setVisible(true);
        }
        tabs.setSelectedIndex(SOURCE_TAB);
        tabs.revalidate();
        tabs.repaint();
    }

    /**
     * Swing's plain text view does not paint extremely long logical lines, so
     * minified bundles would show a blank Source tab. Wrapping only files with
     * very long lines keeps normal source unwrapped and readable.
     */
    private void setSourceText(String text) {
        boolean wrap = hasVeryLongLine(text);
        sourceArea.setLineWrap(wrap);
        sourceArea.setWrapStyleWord(false);
        sourceArea.setText(text);
    }

    private static boolean hasVeryLongLine(String text) {
        int run = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '\n' || c == '\r') {
                run = 0;
            } else if (++run > LONG_LINE_THRESHOLD) {
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------
    // Table construction and data
    // ------------------------------------------------------------------

    private static DefaultTableModel tableModel(String... columns) {
        return new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
    }

    private JTable createTable(DefaultTableModel model, int[] widths, int lineColumn) {
        JTable table = new JTable(model);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(Math.max(20, table.getRowHeight()));
        table.setFillsViewportHeight(true);
        for (int i = 0; i < widths.length && i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        DefaultTableCellRenderer renderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable source, Object value, boolean selected,
                                                           boolean focused, int row, int column) {
                Component component = super.getTableCellRendererComponent(source, value, selected,
                        focused, row, column);
                setToolTipText(value == null ? null : value.toString());
                return component;
            }
        };
        table.setDefaultRenderer(Object.class, renderer);
        installJump(table, lineColumn);
        installCopy(table);
        return table;
    }

    private static JScrollPane scroll(JComponent view) {
        JScrollPane scroll = new JScrollPane(view);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        return scroll;
    }

    private void clearModels() {
        endpointsModel.setRowCount(0);
        secretsModel.setRowCount(0);
        ajaxModel.setRowCount(0);
        domModel.setRowCount(0);
        functionsModel.setRowCount(0);
    }

    private void fillEndpoints(AnalysisResult result) {
        List<Object[]> rows = new ArrayList<>();
        for (EndpointFinding endpoint : result.endpoints) {
            rows.add(new Object[]{endpoint.value(), endpoint.type(), endpoint.line()});
        }
        addRows(endpointsModel, rows);
    }

    private void fillSecrets(AnalysisResult result) {
        List<Object[]> rows = new ArrayList<>();
        for (SensitiveFinding finding : result.sensitiveFindings) {
            rows.add(new Object[]{finding.keyword(), finding.value(), finding.line(),
                    finding.context()});
        }
        addRows(secretsModel, rows);
    }

    private void fillAjax(AnalysisResult result) {
        List<Object[]> rows = new ArrayList<>();
        for (AjaxFinding call : result.ajaxCalls) {
            rows.add(new Object[]{call.type(), call.method(), call.url(),
                    String.join(", ", call.parameters()), call.line()});
        }
        addRows(ajaxModel, rows);
    }

    private void fillDomXss(AnalysisResult result) {
        List<Object[]> rows = new ArrayList<>();
        for (DomXssFinding finding : result.domXssFindings) {
            rows.add(new Object[]{finding.sink(), finding.source(), finding.severity(),
                    finding.confidence(), String.join(" -> ", finding.path()), finding.line()});
        }
        addRows(domModel, rows);
    }

    private void fillFunctions(AnalysisResult result) {
        List<Object[]> rows = new ArrayList<>();
        for (FunctionFinding function : result.interestingFunctions) {
            rows.add(new Object[]{function.name(), function.matchedAction(), function.signature(),
                    function.line()});
        }
        addRows(functionsModel, rows);
    }

    private static void addRows(DefaultTableModel model, List<Object[]> rows) {
        for (Object[] row : rows) {
            model.addRow(row);
        }
    }

    private void setCounts(int endpoints, int secrets, int ajax, int dom, int functions) {
        tabs.setTitleAt(ENDPOINTS_TAB, "Endpoints (" + endpoints + ")");
        tabs.setTitleAt(SECRETS_TAB, "Secrets (" + secrets + ")");
        tabs.setTitleAt(AJAX_TAB, "Ajax / Fetch (" + ajax + ")");
        tabs.setTitleAt(DOM_TAB, "DOM XSS (" + dom + ")");
        tabs.setTitleAt(FUNCTIONS_TAB, "Functions (" + functions + ")");
    }

    // ------------------------------------------------------------------
    // Source navigation
    // ------------------------------------------------------------------

    private void installJump(JTable table, int lineColumn) {
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent event) {
                if (event.getClickCount() != 2) {
                    return;
                }
                int row = table.getSelectedRow();
                if (row < 0) {
                    return;
                }
                Object value = table.getValueAt(row, lineColumn);
                int line = value instanceof Number number ? number.intValue() : parseLine(value);
                if (line > 0) {
                    jumpToLine(line);
                }
            }
        });
    }

    private static int parseLine(Object value) {
        try {
            return Integer.parseInt(String.valueOf(value).trim());
        } catch (NumberFormatException ignored) {
            return -1;
        }
    }

    private void jumpToLine(int line) {
        sourceArea.getHighlighter().removeAllHighlights();
        int index = Math.max(0, Math.min(line - 1, Math.max(0, sourceArea.getLineCount() - 1)));
        try {
            int start = sourceArea.getLineStartOffset(index);
            int end = Math.min(sourceArea.getLineEndOffset(index), start + MAX_HIGHLIGHT_CHARS);
            sourceArea.setCaretPosition(start);
            sourceArea.moveCaretPosition(end);
            sourceArea.getHighlighter().addHighlight(start, end,
                    new DefaultHighlighter.DefaultHighlightPainter(HIGHLIGHT));
            Rectangle2D bounds = sourceArea.modelToView2D(start);
            if (bounds != null) {
                Rectangle rectangle = bounds.getBounds();
                rectangle.grow(0, 30);
                sourceArea.scrollRectToVisible(rectangle);
            }
        } catch (BadLocationException ignored) {
            return;
        }
        tabs.setSelectedIndex(SOURCE_TAB);
    }

    private static void installCopy(JTable table) {
        table.getInputMap(JComponent.WHEN_FOCUSED)
                .put(KeyStroke.getKeyStroke("control C"), "js-analyzer-copy");
        table.getActionMap().put("js-analyzer-copy", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent event) {
                StringBuilder builder = new StringBuilder();
                for (int row : table.getSelectedRows()) {
                    for (int column = 0; column < table.getColumnCount(); column++) {
                        if (column > 0) {
                            builder.append('\t');
                        }
                        Object value = table.getValueAt(row, column);
                        builder.append(value == null ? "" : value);
                    }
                    builder.append('\n');
                }
                if (builder.length() > 0) {
                    Toolkit.getDefaultToolkit().getSystemClipboard()
                            .setContents(new StringSelection(builder.toString()), null);
                }
            }
        });
    }

    private Font monoFont() {
        if (api != null) {
            Font font = api.userInterface().currentEditorFont();
            if (font != null) {
                return font;
            }
        }
        return new Font(Font.MONOSPACED, Font.PLAIN, 12);
    }

    private Font displayFont() {
        if (api != null) {
            Font font = api.userInterface().currentDisplayFont();
            if (font != null) {
                return font;
            }
        }
        return new Font(Font.SANS_SERIF, Font.PLAIN, 12);
    }
}
