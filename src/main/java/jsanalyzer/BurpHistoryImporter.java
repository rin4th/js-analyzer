package jsanalyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import jsanalyzer.store.AnalysisStore;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Imports JavaScript responses Burp already holds, from Proxy history and the
 * site map. This covers files seen before the extension was loaded, and files
 * whose live response never reached the HTTP handler (for example because the
 * browser served them from cache).
 *
 * The scan also reports why entries were skipped, so a file that is visible in
 * Burp but absent from the analyzer can be diagnosed.
 */
public final class BurpHistoryImporter {

    private static final int MAX_SAMPLES = 12;

    public static final class Result {
        public final int checked;
        public final int submitted;
        public final int skipped;
        public final int proxyEntries;
        public final int siteMapEntries;
        public final Map<String, Integer> skipReasons;
        public final List<String> samples;
        public final List<String> errors;

        Result(int checked, int submitted, int skipped, int proxyEntries, int siteMapEntries,
               Map<String, Integer> skipReasons, List<String> samples, List<String> errors) {
            this.checked = checked;
            this.submitted = submitted;
            this.skipped = skipped;
            this.proxyEntries = proxyEntries;
            this.siteMapEntries = siteMapEntries;
            this.skipReasons = Map.copyOf(skipReasons);
            this.samples = List.copyOf(samples);
            this.errors = List.copyOf(errors);
        }
    }

    private static final class Counters {
        int checked;
        int submitted;
        int skipped;
        int proxyEntries;
        int siteMapEntries;
        final Map<String, Integer> reasons = new LinkedHashMap<>();
        final List<String> samples = new ArrayList<>();
        final List<String> errors = new ArrayList<>();
        final Set<String> seenUrls = new HashSet<>();
    }

    private BurpHistoryImporter() {
    }

    public static Result scan(MontoyaApi api, AnalysisStore store) {
        return scan(api, store, null);
    }

    public static Result scan(MontoyaApi api, AnalysisStore store, ScriptAutoFetcher autoFetcher) {
        Counters counters = new Counters();

        try {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            counters.proxyEntries = history == null ? 0 : history.size();
            if (history != null) {
                for (ProxyHttpRequestResponse entry : history) {
                    if (entry == null) {
                        continue;
                    }
                    consider(api, store, entry.request(), entry.finalRequest(), entry.response(),
                            entry.url(), counters, autoFetcher);
                }
            }
        } catch (RuntimeException exception) {
            counters.errors.add("Proxy history: " + exception.getMessage());
        }

        try {
            List<HttpRequestResponse> entries = api.siteMap().requestResponses();
            counters.siteMapEntries = entries == null ? 0 : entries.size();
            if (entries != null) {
                for (HttpRequestResponse entry : entries) {
                    if (entry == null) {
                        continue;
                    }
                    consider(api, store, entry.request(), entry.request(),
                            entry.hasResponse() ? entry.response() : null, entry.url(), counters,
                            autoFetcher);
                }
            }
        } catch (RuntimeException exception) {
            counters.errors.add("Site map: " + exception.getMessage());
        }

        return new Result(counters.checked, counters.submitted, counters.skipped,
                counters.proxyEntries, counters.siteMapEntries, counters.reasons,
                counters.samples, counters.errors);
    }

    private static void consider(MontoyaApi api, AnalysisStore store, HttpRequest request,
                                 HttpRequest finalRequest, HttpResponse response, String fallbackUrl,
                                 Counters counters, ScriptAutoFetcher autoFetcher) {
        counters.checked++;
        HttpRequest effective = finalRequest != null ? finalRequest : request;
        String url = effective != null ? effective.url() : fallbackUrl;
        if (response == null) {
            skip(counters, "no stored response",
                    url != null ? url : effective != null ? effective.url() : "", effective, null);
            return;
        }
        if (url == null) {
            skip(counters, "no URL", "", effective, response);
            return;
        }

        boolean inScope = (effective != null && effective.isInScope()) || api.scope().isInScope(url);
        if (!inScope) {
            skip(counters, "out of scope", url, effective, response);
            return;
        }
        short status = response.statusCode();
        if (status < 200 || status >= 300) {
            skip(counters, "status " + status, url, effective, response);
            return;
        }
        int length = response.body().length();
        if (length == 0) {
            skip(counters, "empty body", url, effective, response);
            return;
        }
        if (length > JsDetector.MAX_BODY_BYTES) {
            skip(counters, "larger than 8 MB", url, effective, response);
            return;
        }
        String path = effective != null ? effective.pathWithoutQuery() : pathOf(url);
        String contentType = response.headerValue("Content-Type");
        if (isHtml(path, contentType)) {
            if (autoFetcher != null) {
                if (length <= 2 * 1024 * 1024) {
                    autoFetcher.considerPage(url, response.bodyToString());
                    skip(counters, "HTML page (scripts queued)", url, effective, response);
                } else {
                    skip(counters, "HTML page too large", url, effective, response);
                }
            } else {
                skip(counters, "not JavaScript", url, effective, response);
            }
            return;
        }
        if (!JsDetector.looksLikeJavascript(path, contentType, "x")) {
            skip(counters, "not JavaScript", url, effective, response);
            return;
        }
        String key = AnalysisStore.normalizeKey(url);
        if (!counters.seenUrls.add(key)) {
            skip(counters, "duplicate in this scan", url, effective, response);
            return;
        }
        String body = response.bodyToString();
        if (!JsDetector.looksLikeJavascript(path, contentType, body)) {
            skip(counters, "HTML/JSON body", url, effective, response);
            return;
        }
        store.submit(url, body, status, contentType);
        counters.submitted++;
    }

    private static void skip(Counters counters, String reason, String url, HttpRequest request,
                             HttpResponse response) {
        counters.skipped++;
        counters.reasons.merge(reason, 1, Integer::sum);

        boolean javascriptLooking = request != null && JsDetector.isJavascriptPath(request.pathWithoutQuery())
                || url != null && JsDetector.isJavascriptPath(pathOf(url));
        if (!javascriptLooking) {
            return;
        }
        if (counters.samples.size() >= MAX_SAMPLES) {
            return;
        }
        StringBuilder sample = new StringBuilder(reason).append(" | ").append(url);
        if (response != null) {
            sample.append(" | status ").append(response.statusCode())
                    .append(" | ").append(response.headerValue("Content-Type"))
                    .append(" | ").append(response.body().length()).append(" bytes");
        }
        counters.samples.add(sample.toString());
    }

    private static boolean isHtml(String path, String contentType) {
        if (contentType != null) {
            String lower = contentType.toLowerCase(java.util.Locale.ROOT);
            if (lower.contains("javascript") || lower.contains("ecmascript")) {
                return false;
            }
            if (lower.contains("text/html") || lower.contains("xhtml")) {
                return true;
            }
        }
        String lowerPath = path == null ? "" : path.toLowerCase(java.util.Locale.ROOT);
        return lowerPath.endsWith(".html") || lowerPath.endsWith(".htm")
                || lowerPath.isEmpty() || lowerPath.equals("/");
    }

    static String pathOf(String url) {
        try {
            String path = java.net.URI.create(url).getPath();
            return path == null || path.isEmpty() ? "/" : path;
        } catch (RuntimeException ignored) {
            return "/";
        }
    }
}
