package jsanalyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.sitemap.SiteMap;
import jsanalyzer.store.AnalysisStore;
import jsanalyzer.store.JsFile;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Tests importing JavaScript from Proxy history and the site map. */
public final class BurpHistoryImporterTest {

    private static int passed;
    private static int failed;

    public static void main(String[] args) throws Exception {
        AnalysisStore store = new AnalysisStore();

        HttpRequestResponse proxyJs = siteMapEntry("https://www.unipin.com/js/app.v5.js?id=54d433",
                "/js/app.v5.js", true, 200, "application/javascript",
                "fetch('/api/v5/app');\n", true);
        HttpRequestResponse duplicate = siteMapEntry("https://www.unipin.com/js/app.v5.js?id=other",
                "/js/app.v5.js", true, 200, "application/javascript",
                "fetch('/api/v5/app');\n", true);
        HttpRequestResponse outOfScope = siteMapEntry("https://other.test/js/out.js",
                "/js/out.js", false, 200, "application/javascript", "var x = 1;", true);
        HttpRequestResponse noResponse = siteMapEntry("https://www.unipin.com/js/missing.js",
                "/js/missing.js", true, 200, "application/javascript", "x", false);
        HttpRequestResponse css = siteMapEntry("https://www.unipin.com/css/app.v5.css",
                "/css/app.v5.css", true, 200, "text/css", "body{}", true);

        SiteMap siteMap = proxy(SiteMap.class, Map.of("requestResponses",
                List.of(duplicate, outOfScope, noResponse, css)), null);
        burp.api.montoya.proxy.Proxy proxy = proxy(burp.api.montoya.proxy.Proxy.class,
                Map.of("history", List.of(proxyEntry(proxyJs))), null);
        Scope scope = scopedTo("https://www.unipin.com");
        MontoyaApi api = proxy(MontoyaApi.class,
                Map.of("siteMap", siteMap, "scope", scope, "proxy", proxy), null);

        BurpHistoryImporter.Result result = BurpHistoryImporter.scan(api, store);
        check("history.checked", 5, result.checked);
        check("history.submitted", 1, result.submitted);
        check("history.skipped", 4, result.skipped);
        check("history.proxyEntries", 1, result.proxyEntries);
        check("history.siteMapEntries", 4, result.siteMapEntries);
        check("history.errors", 0, result.errors.size());
        check("history.reasonDuplicates", 1, result.skipReasons.get("duplicate in this scan"));
        check("history.reasonScope", 1, result.skipReasons.get("out of scope"));
        check("history.reasonNoResponse", 1, result.skipReasons.get("no stored response"));
        check("history.reasonNotJs", 1, result.skipReasons.get("not JavaScript"));
        check("history.sampleCount", 3, result.samples.size());
        check("history.sampleHasApp", true,
                result.samples.stream().anyMatch(sample -> sample.contains("app.v5.js")));
        check("history.sampleHasReason", true,
                result.samples.stream().anyMatch(sample -> sample.startsWith("out of scope")));

        long deadline = System.currentTimeMillis() + 5000;
        while (System.currentTimeMillis() < deadline && store.counts().get("analyzed") == 0) {
            Thread.sleep(20);
        }
        List<JsFile> files = store.snapshot();
        check("history.storeSize", 1, files.size());
        if (files.size() == 1) {
            check("history.key", "https://www.unipin.com/js/app.v5.js", files.get(0).key);
            check("history.endpoints", true, files.get(0).endpointCount() >= 1);
        }

        store.shutdown();
        System.out.println("passed: " + passed + ", failed: " + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    private static ProxyHttpRequestResponse proxyEntry(HttpRequestResponse entry) {
        return proxy(ProxyHttpRequestResponse.class, withDefaults(Map.of(
                "request", entry.request(),
                "finalRequest", entry.request(),
                "response", entry.response(),
                "url", entry.url())), null);
    }

    private static HttpRequestResponse siteMapEntry(String url, String path, boolean inScope, int status,
                                                    String contentType, String body, boolean hasResponse) {
        ByteArray bytes = proxy(ByteArray.class, Map.of("length", body.length()), null);
        HttpResponse response = proxy(HttpResponse.class, withDefaults(Map.of(
                "statusCode", (short) status,
                "body", bytes,
                "bodyToString", body,
                "headerValue", contentType)), null);
        HttpRequest request = proxy(HttpRequest.class, withDefaults(Map.of(
                "url", url,
                "pathWithoutQuery", path,
                "isInScope", inScope)), null);
        return proxy(HttpRequestResponse.class, withDefaults(Map.of(
                "hasResponse", hasResponse,
                "response", response,
                "request", request,
                "url", url)), null);
    }

    private static Map<String, Object> withDefaults(Map<String, Object> values) {
        return new HashMap<>(values);
    }

    private static Scope scopedTo(String prefix) {
        return (Scope) Proxy.newProxyInstance(Scope.class.getClassLoader(), new Class<?>[]{Scope.class},
                (proxy, method, args) -> {
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
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, Map<String, Object> values, Object unused) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type},
                (proxy, method, args) -> {
                    String name = method.getName();
                    if (name.equals("toString")) {
                        return type.getSimpleName();
                    }
                    if (name.equals("hashCode")) {
                        return System.identityHashCode(proxy);
                    }
                    if (name.equals("equals")) {
                        return proxy == (args == null ? null : args[0]);
                    }
                    if (values.containsKey(name)) {
                        return values.get(name);
                    }
                    Class<?> returnType = method.getReturnType();
                    if (returnType == boolean.class) {
                        return false;
                    }
                    if (returnType == int.class) {
                        return 0;
                    }
                    if (returnType == short.class) {
                        return (short) 0;
                    }
                    if (returnType == long.class) {
                        return 0L;
                    }
                    if (returnType == byte.class) {
                        return (byte) 0;
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
