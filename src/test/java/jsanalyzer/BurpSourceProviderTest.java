package jsanalyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.sitemap.SiteMap;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

/** Tests the on-demand source fetch used by export and re-analysis. */
public final class BurpSourceProviderTest {

    private static int passed;
    private static int failed;

    public static void main(String[] args) throws Exception {
        // 1. Burp already holds the response: use it, never touch the network.
        AtomicInteger networkCalls = new AtomicInteger();
        MontoyaApi withHistory = api(
                List.of(proxyEntry("https://example.test/app.js?v=1", 200, "from-history")),
                List.of(),
                url -> {
                    networkCalls.incrementAndGet();
                    return exchange(200, "from-network");
                });
        BurpSourceProvider provider = new BurpSourceProvider(withHistory, url -> {
            throw new IllegalStateException("network must not be used when Burp has the response");
        });
        check("source.historyBody", "from-history", provider.fetch("https://example.test/app.js"));
        check("source.historyNoNetwork", 0, networkCalls.get());

        // 2. Site map entries work the same way.
        MontoyaApi withSiteMap = api(List.of(),
                List.of(siteMapEntry("https://example.test/app.js", 200, "from-site-map")),
                url -> exchange(200, "from-network"));
        check("source.siteMapBody", "from-site-map",
                new BurpSourceProvider(withSiteMap, url -> {
                    throw new IllegalStateException("network must not be used");
                }).fetch("https://example.test/app.js"));

        // 3. No stored copy: refetch through Burp's HTTP stack.
        MontoyaApi noCopy = api(List.of(), List.of(), url -> exchange(200, "from-network"));
        check("source.networkBody", "from-network",
                new BurpSourceProvider(noCopy, url -> request(url))
                        .fetch("https://example.test/app.js"));

        // 4. A stored 304 (empty body) is not usable, so the file is refetched.
        MontoyaApi with304 = api(List.of(proxyEntry("https://example.test/app.js", 304, "")),
                List.of(), url -> exchange(200, "after-revalidation"));
        check("source.stored304Ignored", "after-revalidation",
                new BurpSourceProvider(with304, url -> request(url))
                        .fetch("https://example.test/app.js"));

        // 5. Failures surface as IOExceptions carrying the reason.
        MontoyaApi denied = api(List.of(), List.of(), url -> exchange(403, "denied"));
        check("source.403", true, reason(() -> new BurpSourceProvider(denied, url -> request(url))
                .fetch("https://example.test/app.js")).contains("403"));

        MontoyaApi empty = api(List.of(), List.of(), url -> exchange(200, ""));
        check("source.empty", true,
                reason(() -> new BurpSourceProvider(empty, url -> request(url))
                        .fetch("https://example.test/app.js")).contains("empty"));

        MontoyaApi noResponse = api(List.of(), List.of(), url -> null);
        check("source.noResponse", true,
                reason(() -> new BurpSourceProvider(noResponse, url -> request(url))
                        .fetch("https://example.test/app.js")).contains("no response"));

        // 6. Query-string variants resolve to the same stored entry.
        MontoyaApi queryVariant = api(
                List.of(proxyEntry("https://example.test/app.js?id=99", 200, "variant")),
                List.of(), url -> exchange(200, "from-network"));
        check("source.queryVariant", "variant",
                new BurpSourceProvider(queryVariant, url -> {
                    throw new IllegalStateException("network must not be used");
                }).fetch("https://example.test/app.js"));

        System.out.println("passed: " + passed + ", failed: " + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    private static String reason(ThrowingCall call) {
        try {
            call.run();
            return "<no exception>";
        } catch (IOException exception) {
            return exception.getMessage() == null ? "" : exception.getMessage();
        } catch (RuntimeException exception) {
            return exception.toString();
        }
    }

    private interface ThrowingCall {
        void run() throws IOException;
    }

    private static HttpRequest request(String url) {
        return proxy(HttpRequest.class, Map.of("url", url));
    }

    private static HttpRequestResponse exchange(int status, String body) {
        return siteMapEntry("https://example.test/app.js", status, body);
    }

    private static HttpRequestResponse siteMapEntry(String url, int status, String body) {
        ByteArray bytes = proxy(ByteArray.class, Map.of("length", body.length()));
        HttpResponse response = proxy(HttpResponse.class, Map.of(
                "statusCode", (short) status,
                "body", bytes,
                "bodyToString", body,
                "headerValue", "application/javascript"));
        HttpRequest request = proxy(HttpRequest.class, Map.of(
                "url", url,
                "pathWithoutQuery", "/app.js",
                "isInScope", true));
        return proxy(HttpRequestResponse.class, Map.of(
                "hasResponse", true,
                "response", response,
                "request", request,
                "url", url));
    }

    private static ProxyHttpRequestResponse proxyEntry(String url, int status, String body) {
        HttpRequestResponse base = siteMapEntry(url, status, body);
        return proxy(ProxyHttpRequestResponse.class, Map.of(
                "hasResponse", true,
                "request", base.request(),
                "finalRequest", base.request(),
                "response", base.response(),
                "url", url));
    }

    private static MontoyaApi api(List<ProxyHttpRequestResponse> history,
                                  List<HttpRequestResponse> siteMap,
                                  Function<String, HttpRequestResponse> http) {
        Proxy proxy = proxy(Proxy.class, Map.of("history", history));
        SiteMap map = proxy(SiteMap.class, Map.of("requestResponses", siteMap));
        Http httpApi = (Http) java.lang.reflect.Proxy.newProxyInstance(Http.class.getClassLoader(),
                new Class<?>[]{Http.class}, (instance, method, args) -> {
                    String name = method.getName();
                    if (name.equals("sendRequest") && args != null && args.length >= 1) {
                        return http.apply(((HttpRequest) args[0]).url());
                    }
                    return defaultValue(method, instance, args, Map.of());
                });
        return proxy(MontoyaApi.class, Map.of("proxy", proxy, "siteMap", map, "http", httpApi));
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, Map<String, Object> values) {
        return (T) java.lang.reflect.Proxy.newProxyInstance(type.getClassLoader(),
                new Class<?>[]{type}, (instance, method, args) -> {
                    if (values.containsKey(method.getName())) {
                        return values.get(method.getName());
                    }
                    return defaultValue(method, instance, args, values);
                });
    }

    private static Object defaultValue(java.lang.reflect.Method method, Object instance,
                                       Object[] args, Map<String, Object> values) {
        String name = method.getName();
        if (name.equals("toString")) {
            return method.getDeclaringClass().getSimpleName();
        }
        if (name.equals("hashCode")) {
            return System.identityHashCode(instance);
        }
        if (name.equals("equals")) {
            return instance == (args == null ? null : args[0]);
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
