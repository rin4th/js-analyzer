package jsanalyzer.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
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
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;

/**
 * Right-hand pane: findings tabs for the selected JavaScript file.
 *
 * <p>The tabs and their models are created once and only their contents are
 * updated. Rebuilding a JTabbedPane on every selection can crash Swing's tab
 * painting (BasicTabbedPaneUI throws when the tab count changes during a
 * repaint).</p>
 *
 * <p>There is deliberately no source viewer here. A JTextArea holding a
 * multi-megabyte minified bundle, wrapped or not, made Burp's UI freeze when a
 * large file was selected; the findings tables carry the line numbers instead,
 * and the full text is available through Export .js files… or the Burp
 * request/response viewer.</p>
 */
public final class DetailPanel extends JPanel {

    private static final int ENDPOINTS_TAB = 0;
    private static final int SECRETS_TAB = 1;
    private static final int AJAX_TAB = 2;
    private static final int DOM_TAB = 3;
    private static final int FUNCTIONS_TAB = 4;

    private final MontoyaApi api;
    private final Function<String, String> observedMethods;
    private final JLabel urlLabel = new JLabel("No file selected");
    private final JLabel metaLabel = new JLabel(" ");
    private final JLabel parseNote = new JLabel();
    private final JTabbedPane tabs = new JTabbedPane(JTabbedPane.TOP);
    /** File whose findings are on screen; used to resolve relative endpoints. */
    private JsFile currentFile;

    private final DefaultTableModel endpointsModel = tableModel(
            "Endpoint", "Type", "Method", "Observed", "Line");
    private final DefaultTableModel secretsModel = tableModel(
            "Keyword", "Value", "Line", "Context");
    private final DefaultTableModel ajaxModel = tableModel(
            "Type", "Method", "URL", "Parameters", "Line");
    private final DefaultTableModel domModel = tableModel(
            "Sink", "Source", "Severity", "Confidence", "Path", "Line");
    private final DefaultTableModel functionsModel = tableModel(
            "Function", "Action", "Signature", "Line");

    public DetailPanel(MontoyaApi api) {
        this(api, url -> "");
    }

    /**
     * @param observedMethods endpoint value -> methods Burp saw for that path
     *                        ("POST", "GET, POST"), or "" when unknown
     */
    public DetailPanel(MontoyaApi api, Function<String, String> observedMethods) {
        super(new BorderLayout(0, 6));
        this.api = api;
        this.observedMethods = observedMethods == null ? url -> "" : observedMethods;
        setBorder(BorderFactory.createEmptyBorder(4, 8, 8, 8));

        JPanel header = new JPanel(new BorderLayout(0, 2));
        urlLabel.setFont(displayFont().deriveFont(Font.BOLD, displayFont().getSize2D() + 1f));
        metaLabel.setFont(displayFont().deriveFont(Math.max(10f, displayFont().getSize2D() - 1f)));
        metaLabel.setForeground(new Color(0x80, 0x88, 0x94));
        parseNote.setBorder(BorderFactory.createEmptyBorder(2, 4, 0, 0));
        parseNote.setForeground(new Color(0xB0, 0x8A, 0x30));
        parseNote.setVisible(false);
        header.add(urlLabel, BorderLayout.NORTH);
        header.add(metaLabel, BorderLayout.SOUTH);
        add(header, BorderLayout.NORTH);

        JTable endpointsTable = createTable(endpointsModel, new int[]{430, 100, 90, 90, 60});
        installEndpointActions(endpointsTable);
        tabs.addTab("Endpoints", scroll(endpointsTable));
        tabs.addTab("Secrets", scroll(createTable(secretsModel,
                new int[]{90, 480, 60, 220})));
        tabs.addTab("Ajax / Fetch", scroll(createTable(ajaxModel,
                new int[]{110, 80, 420, 300, 60})));
        tabs.addTab("DOM XSS", scroll(createTable(domModel,
                new int[]{190, 240, 80, 90, 380, 60})));
        tabs.addTab("Functions", scroll(createTable(functionsModel,
                new int[]{300, 90, 420, 60})));

        add(tabs, BorderLayout.CENTER);
        add(parseNote, BorderLayout.SOUTH);
    }

    public void show(JsFile file) {
        currentFile = file;
        parseNote.setVisible(false);
        if (file == null) {
            urlLabel.setText("No file selected");
            urlLabel.setToolTipText(null);
            metaLabel.setText("In-scope JavaScript responses are collected automatically.");
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
            if ("Error".equals(file.status)) {
                meta.append(" · failed: ")
                        .append(file.error == null ? "unknown error" : file.error);
            } else {
                meta.append(" · analysis ").append(file.status.toLowerCase()).append('…');
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

        if (result.parseError != null) {
            parseNote.setText("Parser: " + result.parseError + " — results are heuristic.");
            parseNote.setVisible(true);
        }
        tabs.setSelectedIndex(ENDPOINTS_TAB);
        tabs.revalidate();
        tabs.repaint();
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

    private JTable createTable(DefaultTableModel model, int[] widths) {
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
            rows.add(new Object[]{endpoint.value(), endpoint.type(),
                    orDash(endpoint.method()), orDash(observedMethods.apply(endpoint.value())),
                    endpoint.line()});
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

    private static String orDash(String value) {
        return value == null || value.isBlank() ? "—" : value;
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

    // ------------------------------------------------------------------
    // Endpoint actions
    // ------------------------------------------------------------------

    private void installEndpointActions(JTable table) {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem send = new JMenuItem("Send to Repeater");
        send.setToolTipText("Open this endpoint in Repeater with the method the code uses");
        send.addActionListener(event -> sendToRepeater(table));
        JMenuItem copy = new JMenuItem("Copy endpoint");
        copy.addActionListener(event -> copySelectedValue(table));
        menu.add(send);
        menu.add(copy);

        MouseAdapter mouse = new MouseAdapter() {
            private void maybeShow(MouseEvent event) {
                if (!event.isPopupTrigger()) {
                    return;
                }
                int row = table.rowAtPoint(event.getPoint());
                if (row >= 0) {
                    table.setRowSelectionInterval(row, row);
                }
                if (table.getSelectedRow() < 0) {
                    return;
                }
                menu.show(table, event.getX(), event.getY());
            }

            @Override
            public void mousePressed(MouseEvent event) {
                maybeShow(event);
            }

            @Override
            public void mouseReleased(MouseEvent event) {
                maybeShow(event);
            }
        };
        table.addMouseListener(mouse);
    }

    private void sendToRepeater(JTable table) {
        JsFile file = currentFile;
        int row = table.getSelectedRow();
        if (file == null || row < 0 || api == null) {
            return;
        }
        Object value = table.getValueAt(row, 0);
        String endpoint = value == null ? "" : value.toString();
        String url = absoluteUrl(file.url, endpoint);
        if (url == null) {
            log("JS Analyzer: cannot resolve endpoint '" + endpoint + "' to a URL");
            return;
        }
        String method = methodFor(table.getValueAt(row, 2));
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(url).withMethod(method);
            api.repeater().sendToRepeater(request, repeaterTabName(endpoint));
        } catch (RuntimeException exception) {
            log("JS Analyzer: send to Repeater failed: " + exception.getMessage());
        }
    }

    private void copySelectedValue(JTable table) {
        int row = table.getSelectedRow();
        if (row < 0) {
            return;
        }
        Object value = table.getValueAt(row, 0);
        if (value != null) {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(value.toString()), null);
        }
    }

    private void log(String message) {
        if (api == null) {
            return;
        }
        try {
            api.logging().logToOutput(message);
        } catch (RuntimeException ignored) {
            // Logging must never break the UI.
        }
    }

    /** Repeater tab title: the endpoint itself, shortened when it is long. */
    public static String repeaterTabName(String endpoint) {
        String name = endpoint == null ? "" : endpoint.trim();
        if (name.isEmpty()) {
            return "JS endpoint";
        }
        return name.length() <= 48 ? name : "…" + name.substring(name.length() - 47);
    }

    /** Method to send: the first method the code uses ("POST, GET" -> POST), else GET. */
    public static String methodFor(Object cell) {
        String text = cell == null ? "" : cell.toString().trim();
        if (text.isEmpty() || text.equals("—")) {
            return "GET";
        }
        int comma = text.indexOf(',');
        String first = (comma < 0 ? text : text.substring(0, comma)).trim().toUpperCase(Locale.ROOT);
        return first.matches("[A-Z]{1,10}") ? first : "GET";
    }

    /**
     * Resolves an endpoint value against the URL of the JavaScript file it came
     * from (absolute, protocol-relative, root-relative or bare path). Returns
     * null for template fragments, which cannot be turned into a request.
     */
    public static String absoluteUrl(String base, String endpoint) {
        String value = endpoint == null ? "" : endpoint.trim();
        if (value.isEmpty() || value.contains("{") || value.contains("}")) {
            return null;
        }
        if (value.startsWith("http://") || value.startsWith("https://")) {
            return value;
        }
        try {
            java.net.URI baseUri = java.net.URI.create(base);
            if (baseUri.getScheme() == null || baseUri.getHost() == null) {
                return null;
            }
            java.net.URI resolved = baseUri.resolve(value);
            return resolved.isAbsolute() ? resolved.toString() : null;
        } catch (RuntimeException ignored) {
            return null;
        }
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
