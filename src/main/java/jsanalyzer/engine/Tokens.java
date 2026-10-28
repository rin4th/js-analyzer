package jsanalyzer.engine;

import java.util.ArrayList;
import java.util.List;

/** Helpers for working with the flat token list. */
final class Tokens {

    private Tokens() {
    }

    /** Returns the index of the closing bracket for the opening bracket at {@code openIndex}. */
    static int matching(List<Token> tokens, int openIndex) {
        if (openIndex < 0 || openIndex >= tokens.size()) {
            return -1;
        }
        return tokens.get(openIndex).match;
    }

    /** Returns the index of the opening bracket matching the closing bracket at {@code closeIndex}. */
    static int matchingBackwards(List<Token> tokens, int closeIndex) {
        if (closeIndex < 0 || closeIndex >= tokens.size()) {
            return -1;
        }
        return tokens.get(closeIndex).match;
    }

    /**
     * Splits the arguments of the call whose opening parenthesis is at {@code openIndex}.
     * Returns {@code [from, to)} index pairs.
     */
    static List<int[]> splitArguments(List<Token> tokens, int openIndex) {
        List<int[]> parts = new ArrayList<>();
        int close = matching(tokens, openIndex);
        if (close < 0) {
            return parts;
        }
        int start = openIndex + 1;
        int depth = 0;
        for (int i = start; i < close; i++) {
            Token token = tokens.get(i);
            if (token.kind == Token.Kind.PUNCT) {
                switch (token.text) {
                    case "(":
                    case "[":
                    case "{":
                        depth++;
                        break;
                    case ")":
                    case "]":
                    case "}":
                        depth = Math.max(0, depth - 1);
                        break;
                    case ",":
                        if (depth == 0) {
                            parts.add(new int[]{start, i});
                            start = i + 1;
                        }
                        break;
                    default:
                        break;
                }
            }
        }
        parts.add(new int[]{start, close});
        return parts;
    }

    /**
     * Finds the end (exclusive) of the expression that starts at {@code from}.
     * Stops at a top-level semicolon, comma, closing bracket or at a statement
     * keyword that begins a new line.
     */
    static int expressionEnd(List<Token> tokens, int from) {
        int depth = 0;
        for (int i = from; i < tokens.size(); i++) {
            Token token = tokens.get(i);
            if (token.kind == Token.Kind.PUNCT) {
                switch (token.text) {
                    case "(":
                    case "[":
                    case "{":
                        depth++;
                        break;
                    case ")":
                    case "]":
                    case "}":
                        if (depth == 0) {
                            return i;
                        }
                        depth--;
                        break;
                    case ";":
                        if (depth == 0) {
                            return i;
                        }
                        break;
                    case ",":
                        if (depth == 0) {
                            return i;
                        }
                        break;
                    default:
                        break;
                }
            }
            if (depth == 0 && i > from && token.line > tokens.get(i - 1).line
                    && startsStatement(token) && !continues(tokens.get(i - 1))) {
                return i;
            }
        }
        return tokens.size();
    }

    static boolean startsStatement(Token token) {
        if (token.kind != Token.Kind.NAME) {
            return false;
        }
        switch (token.text) {
            case "const":
            case "let":
            case "var":
            case "function":
            case "class":
            case "if":
            case "for":
            case "while":
            case "switch":
            case "try":
            case "return":
            case "throw":
            case "import":
            case "export":
            case "break":
            case "continue":
                return true;
            default:
                return false;
        }
    }

    static boolean continues(Token token) {
        return token.kind == Token.Kind.PUNCT
                && (token.text.equals(".") || token.text.equals("?.") || token.text.equals(",")
                || token.text.equals("+") || token.text.equals("-") || token.text.equals("*")
                || token.text.equals("/") || token.text.equals("=") || token.text.equals("=>")
                || token.text.equals("(") || token.text.equals("[") || token.text.equals("?")
                || token.text.equals(":") || token.text.equals("||") || token.text.equals("&&")
                || token.text.equals("??") || token.text.equals("|") || token.text.equals("&"));
    }

    static String slice(String source, List<Token> tokens, int from, int toExclusive) {
        if (from >= toExclusive || from < 0 || from >= tokens.size()) {
            return "";
        }
        int end = Math.min(toExclusive, tokens.size());
        int startOffset = tokens.get(from).start;
        int endOffset = tokens.get(end - 1).end;
        if (startOffset < 0 || endOffset > source.length() || endOffset < startOffset) {
            return "";
        }
        return source.substring(startOffset, endOffset);
    }

    static String compact(String value) {
        return compact(value, 300);
    }

    static String compact(String value, int limit) {
        String normalized = String.valueOf(value == null ? "" : value).replaceAll("\\s+", " ").trim();
        if (normalized.length() > limit) {
            return normalized.substring(0, Math.max(0, limit - 3)) + "...";
        }
        return normalized;
    }

    static boolean isBlank(int from, int to) {
        return to <= from;
    }
}
