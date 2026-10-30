package jsanalyzer;

import jsanalyzer.model.AnalysisResult;
import jsanalyzer.store.AnalysisStore;
import jsanalyzer.store.JsFile;
import jsanalyzer.ui.AnalyzerTab;
import jsanalyzer.ui.DetailPanel;
import jsanalyzer.ui.FilesTableModel;

import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

/**
 * Headless smoke test for the Burp tab, the dedupe store, and response
 * detection. Swing components are created on the event dispatch thread, but
 * no window is shown.
 */
public final class UiSmokeTest {

    private static int passed;
    private static int failed;

    public static void main(String[] args) throws Exception {
        AnalysisStore store = new AnalysisStore();
        AnalyzerTab[] tab = new AnalyzerTab[1];
        javax.swing.SwingUtilities.invokeAndWait(() -> tab[0] = new AnalyzerTab(null, store));

        String appJs = "const base = '/api/v2';\n"
                + "fetch(base + '/users?active=1', { method: 'POST', body: { name: 'a' } });\n"
                + "const el = document.querySelector('#out');\n"
                + "el.innerHTML = location.hash;\n"
                + "function uploadDocument(file) { return file; }\n";
        String otherJs = "const key = 'secret-token';\n"
                + "export function deleteAccount(id) { return id; }\n";

        store.submit("https://example.test/static/app.js?v=1", appJs, 200, "application/javascript");
        store.submit("https://example.test/static/app.js?v=2", appJs, 200, "application/javascript");
        store.submit("https://example.test/static/other.js", otherJs, 200, "text/javascript");

        waitFor(store, 2);

        Map<String, Integer> counts = store.counts();
        check("store.total", 2, counts.get("total"));
        check("store.analyzed", 2, counts.get("analyzed"));
        check("store.duplicates", 1, counts.get("duplicates"));

        List<JsFile> files = store.snapshot();
        JsFile app = files.get(0);
        check("store.app.hits", 2, app.hits);
        check("store.app.endpoints", 3, app.endpointCount());
        check("store.app.ajax", 1, app.ajaxCount());
        check("store.app.domXss", 1, app.domXssCount());
        check("store.app.functions", 1, app.functionCount());
        check("store.app.url", "https://example.test/static/app.js", app.key);
        check("store.other.secrets", true, files.get(1).secretCount() >= 1);

        // UI model reflects the store.
        FilesTableModel model = (FilesTableModel) field(tab[0], "filesModel");
        check("ui.rows", 2, model.getRowCount());
        JTable table = (JTable) field(tab[0], "filesTable");
        check("ui.tableRows", 2, table.getRowCount());

        javax.swing.SwingUtilities.invokeAndWait(() -> table.setRowSelectionInterval(0, 0));
        JTabbedPane detailTabs = (JTabbedPane) field(field(tab[0], "detail"), "tabs");
        check("ui.detailTabs", 5, detailTabs.getTabCount());
        check("ui.detailTab0", "Endpoints (3)", detailTabs.getTitleAt(0));
        check("ui.detailTab2", "Ajax / Fetch (1)", detailTabs.getTitleAt(2));
        check("ui.detailTab4", "Functions (1)", detailTabs.getTitleAt(4));
        check("ui.selectedTab", 0, detailTabs.getSelectedIndex());

        // There is no source viewer: the findings tables are the whole detail
        // pane, and the line column is what you use to find code elsewhere.
        DetailPanel detailPanel = (DetailPanel) field(tab[0], "detail");
        check("ui.noSourceTextArea", 0, countComponents(detailPanel, javax.swing.JTextArea.class));

        // Endpoints show the method the code calls them with, plus the methods
        // Burp actually observed for that path.
        store.recordRequest("/api/v2/users", "POST");
        store.recordRequest("/api/v2/users", "GET");
        check("store.observed.relative", "GET, POST", store.observedMethods("/api/v2/users"));
        check("store.observed.absolute", "GET, POST",
                store.observedMethods("https://example.test/api/v2/users?active=1"));
        check("store.observed.unknown", "", store.observedMethods("/api/v2/nowhere"));

        javax.swing.SwingUtilities.invokeAndWait(() -> detailPanel.show(app));
        DefaultTableModel endpointsModel = (DefaultTableModel) field(detailPanel, "endpointsModel");
        int called = -1;
        int bare = -1;
        for (int row = 0; row < endpointsModel.getRowCount(); row++) {
            if ("/api/v2/users?active=1".equals(endpointsModel.getValueAt(row, 0))) {
                called = row;
            } else if ("/api/v2".equals(endpointsModel.getValueAt(row, 0))) {
                bare = row;
            }
        }
        check("ui.endpoint.calledRow", true, called >= 0);
        check("ui.endpoint.bareRow", true, bare >= 0);
        if (called >= 0) {
            check("ui.endpoint.method", "POST", endpointsModel.getValueAt(called, 2));
            check("ui.endpoint.observed", "GET, POST", endpointsModel.getValueAt(called, 3));
        }
        if (bare >= 0) {
            check("ui.endpoint.noMethod", "\u2014", endpointsModel.getValueAt(bare, 2));
            check("ui.endpoint.noObserved", "\u2014", endpointsModel.getValueAt(bare, 3));
        }

        // Selecting an enormous minified file used to block Burp while a
        // JTextArea was filled with the whole bundle.
        StringBuilder big = new StringBuilder(743_000);
        while (big.length() < 743_000) {
            big.append("var a123=function(e){return e+1};");
        }
        big.append("\n//# sourceMappingURL=app.v5.js.map");
        String bigSource = big.toString();
        JsFile bigFile = new JsFile("https://example.test/big.js",
                "https://example.test/big.js?id=54d433", "example.test", 200,
                "application/javascript", bigSource.length(), "big-hash");
        bigFile.status = "Analyzed";
        bigFile.result = new AnalysisResult(List.of(), List.of(), List.of(), List.of(), List.of(),
                null, 2, bigSource.length(), 2674);
        long[] bigShowMs = new long[1];
        javax.swing.SwingUtilities.invokeAndWait(() -> {
            long start = System.nanoTime();
            detailPanel.show(bigFile);
            bigShowMs[0] = (System.nanoTime() - start) / 1_000_000L;
        });
        check("ui.bigFileTabs", 5, detailTabs.getTabCount());
        check("ui.bigFileShownFast", true, bigShowMs[0] < 2000);

        javax.swing.SwingUtilities.invokeAndWait(() -> detailPanel.show(app));
        check("ui.tabsAfterShow", 5, detailTabs.getTabCount());

        // Changed content for the same URL is re-analyzed in place.
        String updated = "fetch('/api/v2/new-endpoint');\n";
        JsFile updatedFile = store.submit("https://example.test/static/app.js?v=3", updated, 200,
                "application/javascript");
        check("store.updated.sameEntry", true, updatedFile == app);
        waitForText(store, app, "Analyzed");
        check("store.updated.endpoints", 1, app.endpointCount());

        // Only findings are retained: there is no source field to hold bodies,
        // and re-analysis refetches the file through the source provider.
        check("store.noSourceField", false, hasField(JsFile.class, "source"));
        store.setSourceProvider(url -> "fetch('/api/v3/refetched');\nconst key = 'token';\n");
        store.reanalyze(app);
        waitForText(store, app, "Analyzed");
        check("store.reanalyze.endpoints", 1, app.endpointCount());
        check("store.reanalyze.secrets", true, app.secretCount() >= 1);
        check("store.reanalyze.hashUpdated", true,
                jsanalyzer.store.AnalysisStore.contentHash(
                        "fetch('/api/v3/refetched');\nconst key = 'token';\n")
                        .equals(app.contentHash));

        // A failed refetch is reported on the entry instead of keeping stale results.
        store.setSourceProvider(url -> {
            throw new java.io.IOException("HTTP 403 when refetching");
        });
        store.reanalyze(app);
        waitForText(store, app, "Error");
        check("store.reanalyze.error", true, app.error != null && app.error.contains("403"));
        check("store.reanalyze.resultCleared", true, app.result == null);

        // Detector behaviour.
        check("detect.js.extension", true, JsDetector.looksLikeJavascript("/app.js", "text/plain", "var a = 1;"));
        check("detect.js.mime", true, JsDetector.looksLikeJavascript("/bundle", "application/javascript", "var a = 1;"));
        check("detect.html", false, JsDetector.looksLikeJavascript("/app.js", "text/html", "<!DOCTYPE html><html></html>"));
        check("detect.json", false, JsDetector.looksLikeJavascript("/data.js", "application/json", "{}"));
        check("detect.css", false, JsDetector.looksLikeJavascript("/style.css", "text/css", "body{}"));
        check("detect.map", false, JsDetector.looksLikeJavascript("/app.js.map", "application/json", "{}"));

        store.shutdown();
        System.out.println();
        System.out.println("passed: " + passed + ", failed: " + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    private static void waitFor(AnalysisStore store, int analyzedTarget) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 10_000;
        while (System.currentTimeMillis() < deadline) {
            if (store.counts().get("analyzed") >= analyzedTarget
                    && store.counts().get("queued") == 0) {
                return;
            }
            Thread.sleep(25);
        }
        throw new IllegalStateException("Timed out waiting for analysis: " + store.counts());
    }

    private static void waitForText(AnalysisStore store, JsFile file, String status)
            throws InterruptedException {
        long deadline = System.currentTimeMillis() + 10_000;
        while (System.currentTimeMillis() < deadline) {
            if (status.equals(file.status)) {
                Thread.sleep(25);
                return;
            }
            Thread.sleep(25);
        }
        throw new IllegalStateException("Timed out waiting for status " + status);
    }

    private static int countComponents(java.awt.Container root, Class<?> type) {
        int count = 0;
        for (java.awt.Component component : root.getComponents()) {
            if (type.isInstance(component)) {
                count++;
            }
            if (component instanceof java.awt.Container container) {
                count += countComponents(container, type);
            }
        }
        return count;
    }

    private static boolean hasField(Class<?> type, String name) {
        try {
            type.getDeclaredField(name);
            return true;
        } catch (NoSuchFieldException ignored) {
            return false;
        }
    }

    private static Object field(Object target, String name) throws Exception {
        Class<?> type = target.getClass();
        while (type != null) {
            try {
                Field field = type.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(target);
            } catch (NoSuchFieldException ignored) {
                type = type.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }

    private static void check(String name, Object expected, Object actual) {
        if (java.util.Objects.equals(expected, actual)) {
            passed++;
        } else {
            failed++;
            System.out.println("FAIL " + name + " expected <" + expected + "> but was <" + actual + ">");
        }
    }
}