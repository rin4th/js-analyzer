package jsanalyzer.model;

/** Endpoint-like string recovered from a JavaScript file. */
public record EndpointFinding(String value, String type, int line) {
}
