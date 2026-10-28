package jsanalyzer.store;

import jsanalyzer.model.AnalysisResult;

/** One JavaScript file seen in scope, with its analysis state. */
public final class JsFile {

    public final String key;
    public final String url;
    public final String host;
    public final long firstSeen;

    public volatile String contentType;
    public volatile int statusCode;
    public volatile int size;
    public volatile String contentHash;
    public volatile String source;
    public volatile String status = "Queued";
    public volatile String error;
    public volatile AnalysisResult result;
    public volatile long lastSeen;
    public volatile int hits = 1;

    public JsFile(String key, String url, String host, int statusCode, String contentType, int size,
                  String contentHash, String source) {
        this.key = key;
        this.url = url;
        this.host = host;
        this.statusCode = statusCode;
        this.contentType = contentType;
        this.size = size;
        this.contentHash = contentHash;
        this.source = source;
        this.firstSeen = System.currentTimeMillis();
        this.lastSeen = firstSeen;
    }

    public int endpointCount() {
        return result == null ? 0 : result.endpoints.size();
    }

    public int secretCount() {
        return result == null ? 0 : result.sensitiveFindings.size();
    }

    public int ajaxCount() {
        return result == null ? 0 : result.ajaxCalls.size();
    }

    public int domXssCount() {
        return result == null ? 0 : result.domXssFindings.size();
    }

    public int functionCount() {
        return result == null ? 0 : result.interestingFunctions.size();
    }
}
