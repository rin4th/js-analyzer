package jsanalyzer.engine;

/**
 * A name bound to an expression.
 *
 * <p>{@code from}/{@code to} are indices into the token list the binding was
 * collected from and are only valid against that list. {@code text} is the
 * expression's source text, which stays valid anywhere: template literal
 * expressions are re-lexed on their own, so their token indices have nothing to
 * do with the file-wide list.</p>
 */
final class Binding {

    final int from;
    final int to;
    final String text;

    Binding(int from, int to, String text) {
        this.from = from;
        this.to = to;
        this.text = text == null ? "" : text;
    }

    /** Whether the token range points inside a token list of {@code tokenCount} tokens. */
    boolean fits(int tokenCount) {
        return from >= 0 && from < to && to <= tokenCount;
    }

    @Override
    public String toString() {
        return "Binding[" + from + "," + to + ")=" + text;
    }
}
