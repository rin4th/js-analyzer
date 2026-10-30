package jsanalyzer.ui;

import burp.api.montoya.MontoyaApi;
import jsanalyzer.BurpHistoryImporter;
import jsanalyzer.ManualFetcher;
import jsanalyzer.ScriptAutoFetcher;
import jsanalyzer.store.AnalysisStore;
import jsanalyzer.store.JsFile;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/** The Burp suite tab listing in-scope JavaScript files and their findings. */
public final class AnalyzerTab extends JPanel implements AnalysisStore.Listener {

    private final MontoyaApi api;
    private final AnalysisStore store;
    private final ScriptAutoFetcher autoFetcher;
    private final DetailPanel detail;
    private final FilesTableModel filesModel = new FilesTableModel();
    private final JTable filesTable = new JTable(filesModel);
    private final TableRowSorter<FilesTableModel> sorter = new TableRowSorter<>(filesModel);
    private final JTextField filterField = new JTextField(22);
    private final JLabel statusLabel = new JLabel(" ");

    public AnalyzerTab(MontoyaApi api, AnalysisStore store) {
        this(api, store, null);
    }

    public AnalyzerTab(MontoyaApi api, AnalysisStore store, ScriptAutoFetcher autoFetcher) {
        super(new BorderLayout(0, 0));
        this.api = api;
        this.store = store;
        this.autoFetcher = autoFetcher;
        this.detail = new DetailPanel(api, store::observedMethods);
        store.addListener(this);
        buildUi(api);
        refresh();
    }

    private void buildUi(MontoyaApi api) {
        JPanel toolbar = new JPanel(new BorderLayout(8, 0));
        toolbar.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JLabel filterLabel = new JLabel("Filter");
        filterField.putClientProperty("JTextField.placeholderText", "URL text…");
        filterField.setToolTipText("Filter the file list by URL");
        filterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent event) {
                applyFilter();
            }

            @Override
            public void removeUpdate(DocumentEvent event) {
                applyFilter();
            }

            @Override
            public void changedUpdate(DocumentEvent event) {
                applyFilter();
            }
        });
        JButton reanalyze = new JButton("Re-analyze");
        reanalyze.setToolTipText("Fetch the file again and re-run the analysis (sources are not kept in memory)");
        reanalyze.addActionListener(event -> {
            JsFile file = selectedFile();
            if (file == null) {
                return;
            }
            store.reanalyze(file);
        });
        JButton remove = new JButton("Remove");
        remove.addActionListener(event -> {
            JsFile file = selectedFile();
            if (file != null) {
                store.remove(file);
            }
        });
        JButton clear = new JButton("Clear all");
        clear.addActionListener(event -> {
            if (store.size() == 0) {
                return;
            }
            int choice = JOptionPane.showConfirmDialog(this,
                    "Remove all " + store.size() + " collected JavaScript files?",
                    "JS Analyzer", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (choice == JOptionPane.OK_OPTION) {
                store.clear();
            }
        });
        JButton export = new JButton("Export report…");
        export.addActionListener(event -> exportReport());
        JButton exportSources = new JButton("Export .js files…");
        exportSources.setToolTipText("Fetch every collected file again and write it to a folder, with a manifest "
                + "(only findings are kept in memory)");
        exportSources.addActionListener(event -> exportSources(exportSources));
        JButton scanSiteMap = new JButton("Scan Burp history");
        scanSiteMap.setToolTipText("Analyze in-scope JavaScript responses already stored in Proxy history and the site map");
        scanSiteMap.addActionListener(event -> scanHistory(scanSiteMap));
        JButton fetchUrl = new JButton("Fetch URL…");
        fetchUrl.setToolTipText("Fetch a JavaScript URL through Burp and analyze it (bypasses browser and service-worker caches)");
        fetchUrl.addActionListener(event -> fetchUrl(fetchUrl));

        actions.add(filterLabel);
        actions.add(filterField);
        actions.add(reanalyze);
        actions.add(remove);
        actions.add(clear);
        actions.add(export);
        actions.add(exportSources);
        actions.add(scanSiteMap);
        actions.add(fetchUrl);
        toolbar.add(actions, BorderLayout.WEST);

        statusLabel.setFont(statusLabel.getFont().deriveFont(Math.max(10f,
                statusLabel.getFont().getSize2D() - 1f)));
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));
        if (autoFetcher != null) {
            JCheckBox autoFetch = new JCheckBox("Auto-fetch scripts", autoFetcher.isEnabled());
            autoFetch.setToolTipText("Fetch missing script src URLs from in-scope HTML pages "
                    + "through Burp (bypasses browser and service-worker caches)");
            autoFetch.addActionListener(event -> autoFetcher.setEnabled(autoFetch.isSelected()));
            statusPanel.add(autoFetch);
        }
        statusPanel.add(statusLabel);
        JPanel statusBar = new JPanel(new BorderLayout());
        statusBar.setBorder(BorderFactory.createEmptyBorder(0, 8, 4, 8));
        statusBar.add(statusPanel, BorderLayout.EAST);

        filesTable.setAutoCreateRowSorter(false);
        filesTable.setRowSorter(sorter);
        filesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        filesTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        filesTable.setFillsViewportHeight(true);
        filesTable.setRowHeight(Math.max(20, filesTable.getRowHeight()));
        TableColumnModel columns = filesTable.getColumnModel();
        int[] widths = {440, 80, 70, 50, 70, 60, 60, 60, 50, 70};
        for (int i = 0; i < widths.length && i < columns.getColumnCount(); i++) {
            columns.getColumn(i).setPreferredWidth(widths[i]);
        }
        filesTable.getSelectionModel().addListSelectionListener(event -> {
            if (event.getValueIsAdjusting()) {
                return;
            }
            detail.show(selectedFile());
        });
        installContextMenu();

        JScrollPane filesScroll = new JScrollPane(filesTable);
        filesScroll.setBorder(BorderFactory.createEmptyBorder());

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, filesScroll, detail);
        split.setResizeWeight(0.34);
        split.setDividerLocation(0.34);
        split.setBorder(BorderFactory.createEmptyBorder());

        JPanel north = new JPanel(new BorderLayout());
        north.add(toolbar, BorderLayout.NORTH);
        north.add(statusBar, BorderLayout.SOUTH);
        add(north, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
        setPreferredSize(new Dimension(1100, 640));

        if (api != null) {
            try {
                api.userInterface().applyThemeToComponent(this);
            } catch (RuntimeException ignored) {
                // Older Montoya builds do not theme components; the tab still works.
            }
        }
    }

    private void installContextMenu() {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(event -> {
            JsFile file = selectedFile();
            if (file != null) {
                copyToClipboard(file.url);
            }
        });
        JMenuItem copyReport = new JMenuItem("Copy report for this file");
        copyReport.addActionListener(event -> {
            JsFile file = selectedFile();
            if (file != null) {
                copyToClipboard(ReportBuilder.build(file));
            }
        });
        JMenuItem reanalyze = new JMenuItem("Re-analyze");
        reanalyze.addActionListener(event -> {
            JsFile file = selectedFile();
            if (file != null) {
                store.reanalyze(file);
            }
        });
        JMenuItem remove = new JMenuItem("Remove from list");
        remove.addActionListener(event -> {
            JsFile file = selectedFile();
            if (file != null) {
                store.remove(file);
            }
        });
        JMenuItem open = new JMenuItem("Open URL in browser");
        open.addActionListener(event -> {
            JsFile file = selectedFile();
            if (file == null) {
                return;
            }
            try {
                if (Desktop.isDesktopSupported()
                        && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                    Desktop.getDesktop().browse(URI.create(file.url));
                }
            } catch (IOException | RuntimeException ignored) {
                // Browsing is a convenience only.
            }
        });
        menu.add(copyUrl);
        menu.add(copyReport);
        menu.addSeparator();
        menu.add(reanalyze);
        menu.add(remove);
        menu.addSeparator();
        menu.add(open);

        MouseAdapter mouse = new MouseAdapter() {
            private void maybeShow(MouseEvent event) {
                if (!event.isPopupTrigger()) {
                    return;
                }
                int row = filesTable.rowAtPoint(event.getPoint());
                if (row >= 0) {
                    filesTable.setRowSelectionInterval(row, row);
                }
                menu.show(filesTable, event.getX(), event.getY());
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
        filesTable.addMouseListener(mouse);
    }

    private void exportReport() {
        List<JsFile> files = store.snapshot();
        if (files.isEmpty()) {
            JOptionPane.showMessageDialog(this, "There is nothing to export yet.",
                    "JS Analyzer", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export JS Analyzer report");
        chooser.setSelectedFile(new java.io.File("js-analyzer-report.txt"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path target = chooser.getSelectedFile().toPath();
        try {
            Files.writeString(target, ReportBuilder.build(files), StandardCharsets.UTF_8);
        } catch (IOException exception) {
            JOptionPane.showMessageDialog(this, "Could not write report: " + exception.getMessage(),
                    "JS Analyzer", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void fetchUrl(JButton button) {
        if (api == null) {
            return;
        }
        String suggestion = "";
        try {
            java.awt.datatransfer.Transferable contents = Toolkit.getDefaultToolkit()
                    .getSystemClipboard().getContents(null);
            if (contents != null && contents.isDataFlavorSupported(
                    java.awt.datatransfer.DataFlavor.stringFlavor)) {
                String text = String.valueOf(contents.getTransferData(
                        java.awt.datatransfer.DataFlavor.stringFlavor)).trim();
                if (text.startsWith("http://") || text.startsWith("https://")) {
                    suggestion = text;
                }
            }
        } catch (Exception ignored) {
            // Clipboard prefill is a convenience only.
        }
        String url = (String) JOptionPane.showInputDialog(this,
                "JavaScript URL to fetch through Burp:\n"
                        + "(use this when the browser serves the file from cache)",
                "Fetch and analyze URL", JOptionPane.PLAIN_MESSAGE, null, null, suggestion);
        if (url == null || url.isBlank()) {
            return;
        }
        String label = button.getText();
        button.setEnabled(false);
        button.setText("Fetching…");
        Thread worker = new Thread(() -> {
            ManualFetcher.Result result = ManualFetcher.fetch(api, store, url.trim());
            SwingUtilities.invokeLater(() -> {
                button.setText(label);
                button.setEnabled(true);
                JOptionPane.showMessageDialog(this, result.message, "JS Analyzer",
                        result.ok ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.WARNING_MESSAGE);
            });
        }, "js-analyzer-fetch");
        worker.setDaemon(true);
        worker.start();
    }

    private void scanHistory(JButton button) {
        if (api == null) {
            return;
        }
        String label = button.getText();
        button.setEnabled(false);
        button.setText("Scanning…");
        Thread worker = new Thread(() -> {
            BurpHistoryImporter.Result result = BurpHistoryImporter.scan(api, store, autoFetcher);
            SwingUtilities.invokeLater(() -> {
                button.setText(label);
                button.setEnabled(true);
                showScanReport(result);
            });
        }, "js-analyzer-history");
        worker.setDaemon(true);
        worker.start();
    }

    private void showScanReport(BurpHistoryImporter.Result result) {
        StringBuilder report = new StringBuilder();
        report.append("Checked ").append(result.checked).append(" stored entries (proxy history ")
                .append(result.proxyEntries).append(", site map ").append(result.siteMapEntries)
                .append(")\n");
        report.append("Submitted ").append(result.submitted).append(" JavaScript response(s)\n");
        report.append("Skipped ").append(result.skipped).append('\n');
        int outOfScope = 0;
        for (java.util.Map.Entry<String, Integer> reason : result.skipReasons.entrySet()) {
            report.append("  ").append(reason.getKey()).append(": ")
                    .append(reason.getValue()).append('\n');
            if (reason.getKey().equals("out of scope")) {
                outOfScope = reason.getValue();
            }
        }
        if (!result.samples.isEmpty()) {
            report.append("\nJavaScript-looking entries that were skipped:\n");
            for (String sample : result.samples) {
                report.append("  ").append(sample).append('\n');
            }
        }
        if (!result.errors.isEmpty()) {
            report.append("\nIssues:\n");
            for (String error : result.errors) {
                report.append("  ").append(error).append('\n');
            }
        }
        if (result.checked == 0) {
            report.append("\nBurp has no stored responses yet. Load the file in the Burp browser "
                    + "and try again.\n");
        }
        if (outOfScope > 0) {
            report.append("\n").append(outOfScope)
                    .append(" entries were skipped because their host is outside Target → Scope.\n");
        }
        report.append("\nFiles are stored once per URL without the query string; if the file was "
                + "already analyzed it will not be duplicated.");

        JTextArea area = new JTextArea(report.toString());
        area.setEditable(false);
        area.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, 12));
        area.setCaretPosition(0);
        JScrollPane scroll = new JScrollPane(area);
        scroll.setPreferredSize(new java.awt.Dimension(760, 380));
        JOptionPane.showMessageDialog(this, scroll, "JS Analyzer — Burp history scan",
                result.errors.isEmpty() ? JOptionPane.INFORMATION_MESSAGE
                        : JOptionPane.WARNING_MESSAGE);
    }

    private void exportSources(JButton button) {
        List<JsFile> files = store.snapshot();
        if (files.isEmpty()) {
            JOptionPane.showMessageDialog(this, "There is nothing to export yet.",
                    "JS Analyzer", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Choose a folder for the collected JavaScript files");
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setSelectedFile(new java.io.File("js-analyzer-files"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path target = chooser.getSelectedFile().toPath();
        String label = button.getText();
        button.setEnabled(false);
        button.setText("Exporting…");
        // Sources are not kept in memory: each file is fetched again and
        // written straight to disk, so this is network-bound and must not run
        // on the EDT.
        Thread worker = new Thread(() -> {
            SourceExporter.Result result = SourceExporter.export(files, target,
                    store.sourceProvider(), (done, total, url) -> SwingUtilities.invokeLater(
                            () -> button.setText("Exporting " + done + "/" + total + "…")));
            SwingUtilities.invokeLater(() -> {
                button.setText(label);
                button.setEnabled(true);
                showExportReport(result);
            });
        }, "js-analyzer-export");
        worker.setDaemon(true);
        worker.start();
    }

    private void showExportReport(SourceExporter.Result result) {
        StringBuilder message = new StringBuilder();
        message.append("Exported ").append(result.exported).append(" JavaScript file(s) to\n")
                .append(result.directory);
        if (result.skipped > 0) {
            message.append("\nSkipped: ").append(result.skipped);
        }
        if (result.changed > 0) {
            message.append("\nContent changed since analysis: ").append(result.changed)
                    .append(" (marked content_changed=yes in _manifest.tsv)");
        }
        if (!result.errors.isEmpty()) {
            message.append("\n\nFirst issue: ").append(result.errors.get(0));
        }
        JOptionPane.showMessageDialog(this, message.toString(), "JS Analyzer",
                result.errors.isEmpty() ? JOptionPane.INFORMATION_MESSAGE
                        : JOptionPane.WARNING_MESSAGE);
    }

    private static void copyToClipboard(String value) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(value), null);
    }

    private JsFile selectedFile() {
        int viewRow = filesTable.getSelectedRow();
        if (viewRow < 0 || viewRow >= filesModel.getRowCount()) {
            return null;
        }
        int modelRow = filesTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= filesModel.getRowCount()) {
            return null;
        }
        return filesModel.get(modelRow);
    }

    private void applyFilter() {
        String text = filterField.getText().trim();
        if (text.isEmpty()) {
            sorter.setRowFilter(null);
        } else {
            sorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(text), 0));
        }
    }

    @Override
    public void filesChanged() {
        SwingUtilities.invokeLater(this::refresh);
    }

    private void refresh() {
        JsFile selected = selectedFile();
        filesModel.setFiles(store.snapshot());
        applyFilter();

        Map<String, Integer> counts = store.counts();
        StringBuilder status = new StringBuilder();
        status.append(counts.get("total")).append(" files · ")
                .append(counts.get("analyzed")).append(" analyzed · ")
                .append(counts.get("queued")).append(" queued · ")
                .append(counts.get("errors")).append(" errors · ")
                .append(counts.get("duplicates")).append(" duplicate hits skipped");
        if (autoFetcher != null && autoFetcher.queuedCount() > 0) {
            status.append(" · ").append(autoFetcher.queuedCount()).append(" auto-fetching");
        }
        statusLabel.setText(status.toString());

        if (selected != null) {
            int modelRow = filesModel.indexOf(selected.key);
            if (modelRow >= 0) {
                int viewRow = filesTable.convertRowIndexToView(modelRow);
                if (viewRow >= 0) {
                    filesTable.setRowSelectionInterval(viewRow, viewRow);
                    return;
                }
            }
        }
        if (filesTable.getSelectedRow() < 0) {
            detail.show(null);
        } else {
            detail.show(selectedFile());
        }
    }
}
