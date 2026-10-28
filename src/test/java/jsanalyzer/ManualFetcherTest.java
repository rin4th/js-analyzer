package jsanalyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import jsanalyzer.store.AnalysisStore;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

/** Tests fetching a JavaScript URL through Burp and analyzing the response. */
public final class ManualFetcherTest {

    private static int passed;
    private static int failed;

    public static void main(String[] args) throws Exception {
        AnalysisStore store = new AnalysisStore();
        HttpRequestResponse javascript = exchange(200, "application/javascript",
                "const base = '/api/v2';\nfetch(base + '/items?x=1');\n");
        HttpRequestResponse html = exchange(200, "text/html", "<!DOCTYPE html><html></html>");
        HttpRequestResponse redirect = exchange(302, "text/html", "");

        Http http = httpProxy(javascript);
        MontoyaApi api = proxy(MontoyaApi.class, Map.of("http", http), null);

        java.util.function.Function<String, HttpRequest> requests = url ->
                proxy(HttpRequest.class, Map.of("url", url), null);
        ManualFetcher.Result success = ManualFetcher.fetch(api, store,
                "https://www.unipin.com/js/app.v5.js?id=54d433", requests);
        check("fetch.ok", true, success.ok);
        check("fetch.status", 200, success.status);
        check("fetch.message", true, success.message.contains("analyzing"));

        long deadline = System.currentTimeMillis() + 5000;
        while (System.currentTimeMillis() < deadline && store.counts().get("analyzed") == 0) {
            Thread.sleep(20);
        }
        check("fetch.storeSize", 1, store.size());
        check("fetch.endpoints", true, store.snapshot().get(0).endpointCount() >= 2);

        MontoyaApi htmlApi = proxy(MontoyaApi.class, Map.of("http", httpProxy(html)), null);
        ManualFetcher.Result notJs = ManualFetcher.fetch(htmlApi, store,
                "https://www.unipin.com/not-js", requests);
        check("fetch.notJs", false, notJs.ok);
        check("fetch.notJsMessage", true, notJs.message.contains("not JavaScript"));
        check("fetch.notJsNotStored", 1, store.size());

        MontoyaApi redirectApi = proxy(MontoyaApi.class, Map.of("http", httpProxy(redirect)), null);
        ManualFetcher.Result badStatus = ManualFetcher.fetch(redirectApi, store,
                "https://www.unipin.com/js/redirect.js", requests);
        check("fetch.statusCheck", false, badStatus.ok);
        check("fetch.statusMessage", true, badStatus.message.contains("302"));

        ManualFetcher.Result invalid = ManualFetcher.fetch(api, store, "app.v5.js", requests);
        check("fetch.invalidUrl", false, invalid.ok);

        store.shutdown();
        System.out.println("passed: " + passed + ", failed: " + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    private static HttpRequestResponse exchange(int status, String contentType, String body) {
        ByteArray bytes = proxy(ByteArray.class, Map.of("length", body.length()), null);
        HttpResponse response = proxy(HttpResponse.class, withDefaults(Map.of(
                "statusCode", (short) status,
                "body", bytes,
                "bodyToString", body,
                "headerValue", contentType)), null);
        return proxy(HttpRequestResponse.class, withDefaults(Map.of(
                "hasResponse", true,
                "response", response,
                "url", "https://www.unipin.com/js/app.v5.js")), null);
    }

    private static Http httpProxy(HttpRequestResponse response) {
        return proxy(Http.class, withDefaults(Map.of(
                "sendRequest", response)), null);
    }

    private static Map<String, Object> withDefaults(Map<String, Object> values) {
        return new HashMap<>(values);
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
