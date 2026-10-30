package jsanalyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import jsanalyzer.store.AnalysisStore;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Watches every in-scope response flowing through Burp (Proxy, Repeater,
 * Scanner, etc.), and hands JavaScript bodies to the analysis store exactly
 * once per unique file.
 */
public final class TrafficListener implements HttpHandler {

    private final MontoyaApi api;
    private final AnalysisStore store;
    private final ScriptAutoFetcher autoFetcher;
    private static final int MAX_SKIP_LOGS = 20;

    private final AtomicLong ignored = new AtomicLong();
    private final AtomicLong submitted = new AtomicLong();
    private final AtomicLong loggedSkips = new AtomicLong();

    public TrafficListener(MontoyaApi api, AnalysisStore store) {
        this(api, store, null);
    }

    public TrafficListener(MontoyaApi api, AnalysisStore store, ScriptAutoFetcher autoFetcher) {
        this.api = api;
        this.store = store;
        this.autoFetcher = autoFetcher;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        try {
            String url = requestToBeSent.url();
            boolean inScope = requestToBeSent.isInScope()
                    || (api != null && api.scope().isInScope(url));
            if (inScope) {
                // Remember the method per path so endpoints found as bare
                // strings can show what the browser actually sent.
                store.recordRequest(requestToBeSent.pathWithoutQuery(), requestToBeSent.method());
            }
        } catch (Throwable ignored) {
            // Recording methods must never affect the request pipeline.
        }
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        try {
            process(responseReceived);
        } catch (Throwable throwable) {
            try {
                api.logging().logToError("JS Analyzer: failed to inspect a response", throwable);
            } catch (RuntimeException ignored) {
                // Never let logging failures surface in Burp's HTTP pipeline.
            }
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void process(HttpResponseReceived response) {
        HttpRequest request = response.initiatingRequest();
        String url = request.url();
        String contentType = response.headerValue("Content-Type");
        String path = request.pathWithoutQuery();
        boolean jsLooking = JsDetector.isJavascriptPath(path)
                || contentType != null && contentType.toLowerCase(java.util.Locale.ROOT).contains("javascript");

        if (!(request.isInScope() || api.scope().isInScope(url))) {
            ignored.incrementAndGet();
            logSkip("out of scope", url, jsLooking);
            return;
        }
        short status = response.statusCode();
        if (status < 200 || status >= 300) {
            logSkip("status " + status, url, jsLooking);
            return;
        }
        int length = response.body().length();
        if (length == 0) {
            logSkip("empty body", url, jsLooking);
            return;
        }
        if (length > JsDetector.MAX_BODY_BYTES) {
            logSkip("larger than 8 MB", url, jsLooking);
            return;
        }
        String body = response.bodyToString();
        if (body == null || body.isEmpty()) {
            logSkip("empty decoded body", url, jsLooking);
            return;
        }
        if (isHtml(path, contentType)) {
            if (autoFetcher != null) {
                autoFetcher.considerPage(url, body);
            }
            return;
        }
        if (!JsDetector.looksLikeJavascript(path, contentType, body)) {
            logSkip("not JavaScript (" + contentType + ")", url, jsLooking);
            return;
        }
        store.submit(url, body, status, contentType);
        submitted.incrementAndGet();
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

    /** Logs why a JavaScript-looking response was not analyzed, capped to avoid noise. */
    private void logSkip(String reason, String url, boolean jsLooking) {
        if (!jsLooking || loggedSkips.incrementAndGet() > MAX_SKIP_LOGS) {
            return;
        }
        try {
            api.logging().logToOutput("JS Analyzer skipped (" + reason + "): " + url);
        } catch (RuntimeException ignored) {
            // Logging must never affect traffic processing.
        }
    }

    public long submittedCount() {
        return submitted.get();
    }

    public long ignoredCount() {
        return ignored.get();
    }
}
