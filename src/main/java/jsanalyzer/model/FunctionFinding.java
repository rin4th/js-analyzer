package jsanalyzer.model;

/** Function whose name matches a security-relevant action keyword. */
public record FunctionFinding(String name, String matchedAction, int line, String signature,
                              int start, int end) {
}
