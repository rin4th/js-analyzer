package jsanalyzer;

import jsanalyzer.model.AnalysisResult;
import jsanalyzer.store.AnalysisStore;
import jsanalyzer.store.JsFile;
import jsanalyzer.ui.AnalyzerTab;
import jsanalyzer.ui.DetailPanel;
import jsanalyzer.ui.FilesTableModel;

import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
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
        check("ui.detailTabs", 6, detailTabs.getTabCount());
        check("ui.detailTab0", "Source", detailTabs.getTitleAt(0));

        // Double-clicking a finding row jumps to the highlighted source line.
        javax.swing.JTextArea sourceView = (javax.swing.JTextArea) field(field(tab[0], "detail"),
                "sourceArea");
        javax.swing.SwingUtilities.invokeAndWait(() -> {
            int ajaxTab = -1;
            for (int i = 0; i < detailTabs.getTabCount(); i++) {
                if (detailTabs.getTitleAt(i).startsWith("Ajax")) {
                    ajaxTab = i;
                }
            }
            check("ui.ajaxTabFound", true, ajaxTab >= 0);
            JScrollPane scroll = (JScrollPane) detailTabs.getComponentAt(ajaxTab);
            JTable findings = (JTable) scroll.getViewport().getView();
            findings.setRowSelectionInterval(0, 0);
            java.awt.event.MouseEvent event = new java.awt.event.MouseEvent(findings,
                    java.awt.event.MouseEvent.MOUSE_CLICKED, System.currentTimeMillis(), 0, 10, 10, 2,
                    false, java.awt.event.MouseEvent.BUTTON1);
            for (java.awt.event.MouseListener listener : findings.getMouseListeners()) {
                listener.mouseClicked(event);
            }
            check("ui.jumpTitle", "Source", detailTabs.getTitleAt(detailTabs.getSelectedIndex()));
            check("ui.jumpHighlight", 1, sourceView.getHighlighter().getHighlights().length);
        });

        // A minified file with one enormous logical line must still be readable:
        // Swing does not paint very long unwrapped lines, so wrapping is enabled.
        StringBuilder big = new StringBuilder(743_000);
        while (big.length() < 743_000) {
            big.append("var a123=function(e){return e+1};");
        }
        big.append("\n//# sourceMappingURL=app.v5.js.map");
        String bigSource = big.toString();
        JsFile bigFile = new JsFile("https://example.test/big.js",
                "https://example.test/big.js?id=54d433", "example.test", 200,
                "application/javascript", bigSource.length(), "big-hash", bigSource);
        bigFile.status = "Analyzed";
        bigFile.result = new AnalysisResult(List.of(), List.of(), List.of(), List.of(), List.of(),
                null, 2, bigSource.length(), 2674);
        DetailPanel detailPanel = (DetailPanel) field(tab[0], "detail");
        javax.swing.SwingUtilities.invokeAndWait(() -> detailPanel.show(bigFile));
        check("ui.bigSourceChars", bigSource.length(), sourceView.getText().length());
        check("ui.bigSourceWrapped", true, sourceView.getLineWrap());
        check("ui.bigSourceTabs", 6, detailTabs.getTabCount());
        check("ui.bigSourceTab", "Source", detailTabs.getTitleAt(detailTabs.getSelectedIndex()));

        javax.swing.SwingUtilities.invokeAndWait(() -> detailPanel.show(app));
        check("ui.normalUnwrapped", false, sourceView.getLineWrap());
        check("ui.tabsAfterShow", 6, detailTabs.getTabCount());

        // Changed content for the same URL is re-analyzed in place.
        String updated = "fetch('/api/v2/new-endpoint');\n";
        JsFile updatedFile = store.submit("https://example.test/static/app.js?v=3", updated, 200,
                "application/javascript");
        check("store.updated.sameEntry", true, updatedFile == app);
        waitForText(store, app, "Analyzed");
        check("store.updated.endpoints", 1, app.endpointCount());

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