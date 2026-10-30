package jsanalyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import jsanalyzer.store.AnalysisStore;
import jsanalyzer.store.SourceProvider;

import java.io.IOException;
import java.util.List;
import java.util.function.Function;

/**
 * Supplies JavaScript code on demand for export and re-analysis, after the
 * bodies have been dropped from the analyzer's memory.
 *
 * <p>Burp's own stored responses are tried first: they are the exact bytes that
 * were analyzed, cookies and auth headers already applied. Only when Burp has
 * no stored response is the URL requested again through Burp's HTTP stack,
 * which has no browser cookies — the resulting 401/403 is reported as the
 * reason instead of silently writing an error page.</p>
 */
public final class BurpSourceProvider implements SourceProvider {

    private final MontoyaApi api;
    private final Function<String, HttpRequest> requestFactory;

    public BurpSourceProvider(MontoyaApi api) {
        this(api, HttpRequest::httpRequestFromUrl);
    }

    /** Test seam: the Montoya static factory only works inside Burp. */
    BurpSourceProvider(MontoyaApi api, Function<String, HttpRequest> requestFactory) {
        this.api = api;
        this.requestFactory = requestFactory;
    }

    @Override
    public String fetch(String url) throws IOException {
        String stored = fromStoredResponses(url);
        if (stored != null) {
            return stored;
        }
        return fromNetwork(url);
    }

    /** Latest 2xx stored response for this URL, or null when Burp has none. */
    private String fromStoredResponses(String url) throws IOException {
        String key = AnalysisStore.normalizeKey(url);
        String body = null;
        try {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            if (history != null) {
                for (ProxyHttpRequestResponse entry : history) {
                    if (entry == null || !entry.hasResponse()) {
                        continue;
                    }
                    String entryUrl = entry.url();
                    if (entryUrl != null && key.equals(AnalysisStore.normalizeKey(entryUrl))) {
                        body = usable(entry.response(), body);
                    }
                }
            }
        } catch (RuntimeException exception) {
            throw new IOException("Proxy history: " + exception.getMessage(), exception);
        }
        if (body != null) {
            return body;
        }
        try {
            List<HttpRequestResponse> entries = api.siteMap().requestResponses();
            if (entries != null) {
                for (HttpRequestResponse entry : entries) {
                    if (entry == null || !entry.hasResponse()) {
                        continue;
                    }
                    String entryUrl = entry.request() == null ? null : entry.request().url();
                    if (entryUrl != null && key.equals(AnalysisStore.normalizeKey(entryUrl))) {
                        body = usable(entry.response(), body);
                    }
                }
            }
        } catch (RuntimeException exception) {
            throw new IOException("Site map: " + exception.getMessage(), exception);
        }
        return body;
    }

    private static String usable(HttpResponse response, String previous) {
        if (response == null) {
            return previous;
        }
        short status = response.statusCode();
        int length = response.body().length();
        if (status < 200 || status >= 300 || length == 0 || length > JsDetector.MAX_BODY_BYTES) {
            return previous;
        }
        return response.bodyToString();
    }

    private String fromNetwork(String url) throws IOException {
        HttpRequestResponse exchange;
        try {
            exchange = api.http().sendRequest(requestFactory.apply(url));
        } catch (RuntimeException exception) {
            throw new IOException("Request failed: " + exception.getMessage(), exception);
        }
        if (exchange == null || !exchange.hasResponse() || exchange.response() == null) {
            throw new IOException("Burp returned no response and has no stored copy of this URL");
        }
        HttpResponse response = exchange.response();
        short status = response.statusCode();
        int length = response.body().length();
        if (status < 200 || status >= 300) {
            throw new IOException("HTTP " + status + " when refetching (no browser cookies "
                    + "in Burp's HTTP stack); Burp has no stored copy either");
        }
        if (length == 0) {
            throw new IOException("empty response body");
        }
        if (length > JsDetector.MAX_BODY_BYTES) {
            throw new IOException("response is larger than 8 MB (" + length + " bytes)");
        }
        return response.bodyToString();
    }
}
