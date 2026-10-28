package jsanalyzer.engine;

import java.util.List;

/**
 * A single lexical token of a JavaScript source file. Templates keep their
 * quasi parts and the raw source of each {@code ${...}} expression so the
 * analyzer can rebuild readable strings such as {@code /api/${id}}.
 */
public final class Token {

    public enum Kind {
        NAME, STRING, TEMPLATE, NUMBER, REGEX, PUNCT
    }

    public final Kind kind;
    public final String text;
    public final String value;
    public final int start;
    public final int end;
    public final int line;
    public final List<String> quasis;
    public final List<String> expressions;

    /** Index of the matching bracket token, or -1; filled in by the lexer. */
    public int match = -1;

    public Token(Kind kind, String text, int start, int end, int line) {
        this(kind, text, null, start, end, line, List.of(), List.of());
    }

    public Token(Kind kind, String text, String value, int start, int end, int line) {
        this(kind, text, value, start, end, line, List.of(), List.of());
    }

    public Token(Kind kind, String text, String value, int start, int end, int line,
                 List<String> quasis, List<String> expressions) {
        this.kind = kind;
        this.text = text;
        this.value = value;
        this.start = start;
        this.end = end;
        this.line = line;
        this.quasis = quasis;
        this.expressions = expressions;
    }

    public boolean isPunct(String punct) {
        return kind == Kind.PUNCT && text.equals(punct);
    }

    public boolean isName(String name) {
        return kind == Kind.NAME && text.equals(name);
    }

    @Override
    public String toString() {
        return kind + "(" + text + ")@" + line;
    }
}
