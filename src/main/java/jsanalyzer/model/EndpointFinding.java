package jsanalyzer.model;

/**
 * Endpoint-like string recovered from a JavaScript file.
 *
 * <p>{@code method} is the HTTP method the code calls this endpoint with
 * ({@code fetch(url, {method: 'POST'})}, jQuery {@code type:}, XHR
 * {@code open('POST', url)}). It is empty when the endpoint was only seen as a
 * bare string literal — there is nothing in the source to read it from. Methods
 * Burp actually observed are tracked separately, per request path.</p>
 */
public record EndpointFinding(String value, String type, int line, String method) {

    public EndpointFinding {
        method = method == null ? "" : method;
    }

    /** Endpoint with no method known from the source. */
    public EndpointFinding(String value, String type, int line) {
        this(value, type, line, "");
    }
}
