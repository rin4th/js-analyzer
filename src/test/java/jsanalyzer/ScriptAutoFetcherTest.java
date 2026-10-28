package jsanalyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scope.Scope;
import jsanalyzer.store.AnalysisStore;

import java.lang.reflect.Proxy;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

/** Tests automatic script discovery and fetching from HTML pages. */
public final class ScriptAutoFetcherTest {

    private static int passed;
    private static int failed;

    public static void main(String[] args) throws Exception {
        AnalysisStore store = new AnalysisStore();
        store.submit("https://www.unipin.com/js/existing.js", "var existing = 1;", 200,
                "application/javascript");

        Queue<String> fetched = new ConcurrentLinkedQueue<>();
        ScriptAutoFetcher.Fetcher fetcher = url -> {
            fetched.add(url);
            store.submit(url, "var fetched = 1;", 200, "application/javascript");
            return null;
        };
        ScriptAutoFetcher auto = new ScriptAutoFetcher(apiScopedTo("https://www.unipin.com"), store,
                fetcher);

        String html = "<script src=\"/js/existing.js\"></script>\n"
                + "<script src=\"/js/new-one.js\"></script>\n"
                + "<script src=\"/js/new-two.js?v=2\"></script>\n"
                + "<script src=\"https://cdn.other.test/tracker.js\"></script>\n"
                + "<script src=\"/css/not-a-script.css\"></script>\n"
                + "<script src=\"data:text/javascript,1\"></script>";

        int queued = auto.considerPage("https://www.unipin.com/id/mobile-legends", html);
        check("auto.queued", 2, queued);
        waitFor(fetched, 2);
        check("auto.fetchedCount", 2, fetched.size());
        check("auto.fetchedOne", true, fetched.contains("https://www.unipin.com/js/new-one.js"));
        check("auto.fetchedTwo", true,
                fetched.contains("https://www.unipin.com/js/new-two.js?v=2"));
        check("auto.skipExisting", false, fetched.contains("https://www.unipin.com/js/existing.js"));
        check("auto.skipThirdParty", false, fetched.contains("https://cdn.other.test/tracker.js"));
        check("auto.skipCss", false, fetched.contains("https://www.unipin.com/css/not-a-script.css"));

        int again = auto.considerPage("https://www.unipin.com/id/mobile-legends", html);
        check("auto.queuedAgain", 0, again);

        auto.setEnabled(false);
        int disabled = auto.considerPage("https://www.unipin.com/other",
                "<script src=\"/js/disabled.js\"></script>");
        check("auto.disabled", 0, disabled);
        check("auto.enabledFlag", false, auto.isEnabled());

        auto.shutdown();
        store.shutdown();
        System.out.println("passed: " + passed + ", failed: " + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    private static void waitFor(Queue<String> fetched, int count) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 5000;
        while (System.currentTimeMillis() < deadline && fetched.size() < count) {
            Thread.sleep(20);
        }
    }

    private static MontoyaApi apiScopedTo(String prefix) {
        Scope scope = (Scope) Proxy.newProxyInstance(Scope.class.getClassLoader(),
                new Class<?>[]{Scope.class}, (proxy, method, args) -> {
                    String name = method.getName();
                    if (name.equals("isInScope")) {
                        return ((String) args[0]).startsWith(prefix);
                    }
                    if (name.equals("toString")) {
                        return "Scope";
                    }
                    if (name.equals("hashCode")) {
                        return System.identityHashCode(proxy);
                    }
                    if (name.equals("equals")) {
                        return proxy == args[0];
                    }
                    Class<?> returnType = method.getReturnType();
                    if (returnType == boolean.class) {
                        return false;
                    }
                    if (returnType == int.class) {
                        return 0;
                    }
                    return null;
                });
        return (MontoyaApi) Proxy.newProxyInstance(MontoyaApi.class.getClassLoader(),
                new Class<?>[]{MontoyaApi.class}, (proxy, method, args) -> {
                    String name = method.getName();
                    if (name.equals("scope")) {
                        return scope;
                    }
                    if (name.equals("toString")) {
                        return "MontoyaApi";
                    }
                    if (name.equals("hashCode")) {
                        return System.identityHashCode(proxy);
                    }
                    if (name.equals("equals")) {
                        return proxy == args[0];
                    }
                    Class<?> returnType = method.getReturnType();
                    if (returnType == boolean.class) {
                        return false;
                    }
                    if (returnType == int.class) {
                        return 0;
                    }
                    return null;
                });
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
