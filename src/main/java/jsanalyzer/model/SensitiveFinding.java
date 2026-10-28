package jsanalyzer.model;

/** Sensitive keyword hit (secret-ish name, property or string). */
public record SensitiveFinding(String keyword, String value, int line, String context) {
}
