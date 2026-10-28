package jsanalyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import jsanalyzer.store.AnalysisStore;

/**
 * Fetches a URL through Burp's HTTP stack and analyzes the response. This is
 * the escape hatch for files the browser serves from a service-worker or disk
 * cache, where no live response ever reaches Burp's proxy.
 */
public final class ManualFetcher {

    public static final class Result {
        public final boolean ok;
        public final String message;
        public final int status;
        public final int bytes;

        Result(boolean ok, String message, int status, int bytes) {
            this.ok = ok;
            this.message = message;
            this.status = status;
            this.bytes = bytes;
        }
    }

    private ManualFetcher() {
    }

    public static Result fetch(MontoyaApi api, AnalysisStore store, String rawUrl) {
        return fetch(api, store, rawUrl, HttpRequest::httpRequestFromUrl);
    }

    /** Test seam: Burp's static request factory is only available inside Burp. */
    static Result fetch(MontoyaApi api, AnalysisStore store, String rawUrl,
                        java.util.function.Function<String, HttpRequest> requestFactory) {
        String url = rawUrl == null ? "" : rawUrl.trim();
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            return new Result(false, "Enter a full http:// or https:// URL.", 0, 0);
        }
        HttpRequestResponse exchange;
        try {
            exchange = api.http().sendRequest(requestFactory.apply(url));
        } catch (RuntimeException exception) {
            return new Result(false, "Request failed: " + exception.getMessage(), 0, 0);
        }
        if (exchange == null || !exchange.hasResponse() || exchange.response() == null) {
            return new Result(false, "Burp returned no response for this URL.", 0, 0);
        }
        HttpResponse response = exchange.response();
        short status = response.statusCode();
        int length = response.body().length();
        String contentType = response.headerValue("Content-Type");
        if (status < 200 || status >= 300) {
            return new Result(false, "Server answered HTTP " + status + " (" + length + " bytes).",
                    status, length);
        }
        if (length == 0) {
            return new Result(false, "Response body is empty.", status, 0);
        }
        if (length > JsDetector.MAX_BODY_BYTES) {
            return new Result(false, "Response is larger than 8 MB (" + length + " bytes).",
                    status, length);
        }
        String body = response.bodyToString();
        String path = pathOf(url);
        if (!JsDetector.looksLikeJavascript(path, contentType, body)) {
            return new Result(false, "Response is not JavaScript (Content-Type: " + contentType
                    + ", " + length + " bytes).", status, length);
        }
        store.submit(url, body, status, contentType);
        return new Result(true, "Fetched HTTP " + status + " · " + length
                + " bytes · analyzing…", status, length);
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
