package jsanalyzer.engine;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

/**
 * Small JavaScript tokenizer. It only needs to be good enough for static
 * reconnaissance: comments, strings, template literals, regular expressions,
 * numbers, identifiers and punctuators. Template expressions and regular
 * expressions are handled so their contents are never reported as code.
 */
public final class JsLexer {

    public static final class Result {
        private final List<Token> tokens;
        private final List<String> errors;

        Result(List<Token> tokens, List<String> errors) {
            this.tokens = tokens;
            this.errors = errors;
        }

        public List<Token> tokens() {
            return tokens;
        }

        public List<String> errors() {
            return errors;
        }
    }

    private static final String[] OPERATORS = {
            ">>>=", "===", "!==", "**=", "<<=", ">>=", "...", ">>>", "&&=", "||=", "??=",
            "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "=>", "++", "--", "+=", "-=",
            "*=", "/=", "%=", "&=", "|=", "^=", "<<", ">>", "**",
            "{", "}", "(", ")", "[", "]", ";", ",", "<", ">", "+", "-", "*", "/", "%",
            "&", "|", "^", "!", "~", "?", ":", "=", ".", "@", "#"
    };

    static {
        Arrays.sort(OPERATORS, Comparator.comparingInt(String::length).reversed());
    }

    private final String src;
    private final List<Token> tokens = new ArrayList<>();
    private final List<String> errors = new ArrayList<>();
    private int pos;
    private int line = 1;

    private JsLexer(String src) {
        this.src = src;
    }

    public static Result lex(String source) {
        JsLexer lexer = new JsLexer(source == null ? "" : source);
        lexer.run();
        lexer.indexBrackets();
        return new Result(lexer.tokens, lexer.errors);
    }

    /** Links every bracket token to its partner once, so later lookups are O(1). */
    private void indexBrackets() {
        int[] stack = new int[64];
        int depth = 0;
        for (int i = 0; i < tokens.size(); i++) {
            Token token = tokens.get(i);
            if (token.kind != Token.Kind.PUNCT) {
                continue;
            }
            boolean opening = token.text.equals("(") || token.text.equals("[")
                    || token.text.equals("{");
            boolean closing = token.text.equals(")") || token.text.equals("]")
                    || token.text.equals("}");
            if (!opening && !closing) {
                continue;
            }
            if (opening) {
                if (depth == stack.length) {
                    stack = java.util.Arrays.copyOf(stack, stack.length * 2);
                }
                stack[depth++] = i;
            } else if (depth > 0) {
                int open = depth > 0 ? stack[depth - 1] : -1;
                if (open >= 0 && pairsWith(tokens.get(open).text, token.text)) {
                    depth--;
                    tokens.get(open).match = i;
                    token.match = open;
                }
            }
        }
    }

    private static boolean pairsWith(String opening, String closing) {
        return opening.equals("(") && closing.equals(")")
                || opening.equals("[") && closing.equals("]")
                || opening.equals("{") && closing.equals("}");
    }

    private void run() {
        final int length = src.length();
        while (pos < length) {
            char c = src.charAt(pos);
            if (c == '\n') {
                line++;
                pos++;
                continue;
            }
            if (c == '\r' || c == ' ' || c == '\t' || c == '\f' || c == '\u000B' || c == '\u00A0') {
                pos++;
                continue;
            }
            if (c == '/' && peek(1) == '/') {
                while (pos < length && src.charAt(pos) != '\n') {
                    pos++;
                }
                continue;
            }
            if (c == '/' && peek(1) == '*') {
                int startLine = line;
                pos += 2;
                boolean closed = false;
                while (pos < length) {
                    if (src.charAt(pos) == '*' && peek(1) == '/') {
                        pos += 2;
                        closed = true;
                        break;
                    }
                    if (src.charAt(pos) == '\n') {
                        line++;
                    }
                    pos++;
                }
                if (!closed) {
                    errors.add("Unterminated block comment starting at line " + startLine);
                }
                continue;
            }
            if (c == '\'' || c == '"') {
                lexString(c);
                continue;
            }
            if (c == '`') {
                lexTemplate();
                continue;
            }
            if (Character.isDigit(c) || (c == '.' && Character.isDigit(peek(1)))) {
                lexNumber();
                continue;
            }
            if (isIdentifierStart(c)) {
                lexName();
                continue;
            }
            if (c == '/' && regexAllowed() && tryLexRegex()) {
                continue;
            }
            if (lexOperator()) {
                continue;
            }
            pos++;
        }
    }

    private char peek(int offset) {
        int index = pos + offset;
        return index >= 0 && index < src.length() ? src.charAt(index) : '\0';
    }

    private void lexString(char quote) {
        int start = pos;
        int startLine = line;
        pos++;
        StringBuilder value = new StringBuilder();
        boolean closed = false;
        while (pos < src.length()) {
            char c = src.charAt(pos);
            if (c == '\\') {
                pos++;
                if (pos >= src.length()) {
                    break;
                }
                value.append(unescape());
                continue;
            }
            if (c == quote) {
                pos++;
                closed = true;
                break;
            }
            if (c == '\n') {
                break;
            }
            value.append(c);
            pos++;
        }
        if (!closed) {
            errors.add("Unterminated string literal at line " + startLine);
        }
        tokens.add(new Token(Token.Kind.STRING, src.substring(start, pos), value.toString(), start, pos,
                startLine));
    }

    private void lexTemplate() {
        int start = pos;
        int startLine = line;
        pos++;
        List<String> quasis = new ArrayList<>();
        List<String> expressions = new ArrayList<>();
        StringBuilder value = new StringBuilder();
        boolean closed = false;
        while (pos < src.length()) {
            char c = src.charAt(pos);
            if (c == '\\') {
                pos++;
                if (pos >= src.length()) {
                    break;
                }
                value.append(unescape());
                continue;
            }
            if (c == '`') {
                pos++;
                closed = true;
                break;
            }
            if (c == '$' && peek(1) == '{') {
                quasis.add(value.toString());
                value.setLength(0);
                pos += 2;
                int exprStart = pos;
                int depth = 1;
                while (pos < src.length() && depth > 0) {
                    char d = src.charAt(pos);
                    if (d == '\'' || d == '"') {
                        pos = skipQuoted(pos, d);
                        continue;
                    }
                    if (d == '`') {
                        pos = skipNestedTemplate(pos);
                        continue;
                    }
                    if (d == '/' && peek(1) == '/') {
                        while (pos < src.length() && src.charAt(pos) != '\n') {
                            pos++;
                        }
                        continue;
                    }
                    if (d == '/' && peek(1) == '*') {
                        pos += 2;
                        while (pos + 1 < src.length() && !(src.charAt(pos) == '*' && src.charAt(pos + 1) == '/')) {
                            if (src.charAt(pos) == '\n') {
                                line++;
                            }
                            pos++;
                        }
                        pos = Math.min(src.length(), pos + 2);
                        continue;
                    }
                    if (d == '{') {
                        depth++;
                    } else if (d == '}') {
                        depth--;
                        if (depth == 0) {
                            break;
                        }
                    }
                    if (d == '\n') {
                        line++;
                    }
                    pos++;
                }
                expressions.add(src.substring(exprStart, Math.min(pos, src.length())));
                if (pos < src.length() && src.charAt(pos) == '}') {
                    pos++;
                }
                continue;
            }
            if (c == '\n') {
                line++;
            }
            value.append(c);
            pos++;
        }
        if (closed) {
            quasis.add(value.toString());
        } else {
            quasis.add(value.toString());
            errors.add("Unterminated template literal at line " + startLine);
        }
        tokens.add(new Token(Token.Kind.TEMPLATE, src.substring(start, pos), null, start, pos, startLine,
                quasis, expressions));
    }

    /** Skips a nested quoted string, returning the index after the closing quote. */
    private int skipQuoted(int from, char quote) {
        int index = from + 1;
        while (index < src.length()) {
            char c = src.charAt(index);
            if (c == '\\') {
                index += 2;
                continue;
            }
            if (c == quote) {
                return index + 1;
            }
            if (c == '\n') {
                return index;
            }
            index++;
        }
        return src.length();
    }

    /** Skips a nested template literal (including its expressions). */
    private int skipNestedTemplate(int from) {
        int index = from + 1;
        int depth = 0;
        while (index < src.length()) {
            char c = src.charAt(index);
            if (c == '\\') {
                index += 2;
                continue;
            }
            if (c == '\n') {
                line++;
                index++;
                continue;
            }
            if (depth == 0 && c == '`') {
                return index + 1;
            }
            if (c == '$' && index + 1 < src.length() && src.charAt(index + 1) == '{') {
                depth++;
                index += 2;
                continue;
            }
            if (depth > 0 && c == '}') {
                depth--;
            }
            index++;
        }
        return src.length();
    }

    private void lexNumber() {
        int start = pos;
        while (pos < src.length()) {
            char c = src.charAt(pos);
            if (Character.isLetterOrDigit(c) || c == '.' || c == '_') {
                pos++;
                continue;
            }
            if ((c == '+' || c == '-') && pos > start
                    && (src.charAt(pos - 1) == 'e' || src.charAt(pos - 1) == 'E')) {
                pos++;
                continue;
            }
            break;
        }
        tokens.add(new Token(Token.Kind.NUMBER, src.substring(start, pos), start, pos, line));
    }

    private void lexName() {
        int start = pos;
        if (src.charAt(pos) == '#') {
            // ECMAScript private names: #field
            pos++;
        }
        while (pos < src.length() && isIdentifierPart(src.charAt(pos))) {
            pos++;
        }
        if (pos == start) {
            pos++;
        }
        String text = src.substring(start, pos);
        tokens.add(new Token(Token.Kind.NAME, text, start, pos, line));
    }

    private boolean regexAllowed() {
        if (tokens.isEmpty()) {
            return true;
        }
        Token previous = tokens.get(tokens.size() - 1);
        if (previous.kind == Token.Kind.NAME) {
            switch (previous.text) {
                case "return":
                case "typeof":
                case "instanceof":
                case "in":
                case "of":
                case "new":
                case "delete":
                case "void":
                case "case":
                case "do":
                case "else":
                case "yield":
                case "await":
                    return true;
                default:
                    return false;
            }
        }
        if (previous.kind == Token.Kind.STRING || previous.kind == Token.Kind.TEMPLATE
                || previous.kind == Token.Kind.NUMBER || previous.kind == Token.Kind.REGEX) {
            return false;
        }
        return !(previous.text.equals(")") || previous.text.equals("]")
                || previous.text.equals("++") || previous.text.equals("--"));
    }

    private boolean tryLexRegex() {
        int start = pos;
        int index = pos + 1;
        boolean inClass = false;
        while (index < src.length()) {
            char c = src.charAt(index);
            if (c == '\n' || c == '\r') {
                return false;
            }
            if (c == '\\') {
                index += 2;
                continue;
            }
            if (c == '[') {
                inClass = true;
            } else if (c == ']') {
                inClass = false;
            } else if (c == '/' && !inClass) {
                index++;
                while (index < src.length() && Character.isLetter(src.charAt(index))) {
                    index++;
                }
                tokens.add(new Token(Token.Kind.REGEX, src.substring(start, index), start, index, line));
                pos = index;
                return true;
            }
            index++;
        }
        return false;
    }

    private boolean lexOperator() {
        for (String operator : OPERATORS) {
            if (src.startsWith(operator, pos)) {
                tokens.add(new Token(Token.Kind.PUNCT, operator, pos, pos + operator.length(), line));
                pos += operator.length();
                return true;
            }
        }
        return false;
    }

    private String unescape() {
        char c = src.charAt(pos);
        pos++;
        switch (c) {
            case 'n':
                return "\n";
            case 'r':
                return "\r";
            case 't':
                return "\t";
            case 'b':
                return "\b";
            case 'f':
                return "\f";
            case 'v':
                return "\u000B";
            case '0':
                return "\0";
            case 'x':
                if (pos + 2 <= src.length()) {
                    String hex = src.substring(pos, pos + 2);
                    pos += 2;
                    try {
                        return String.valueOf((char) Integer.parseInt(hex, 16));
                    } catch (NumberFormatException ignored) {
                        return "";
                    }
                }
                return "";
            case 'u':
                if (pos + 4 <= src.length()) {
                    String hex = src.substring(pos, pos + 4);
                    pos += 4;
                    try {
                        return String.valueOf((char) Integer.parseInt(hex, 16));
                    } catch (NumberFormatException ignored) {
                        return "";
                    }
                }
                return "";
            default:
                return String.valueOf(c);
        }
    }

    private static boolean isIdentifierStart(char c) {
        return Character.isLetter(c) || c == '$' || c == '_' || c == '#';
    }

    private static boolean isIdentifierPart(char c) {
        return Character.isLetterOrDigit(c) || c == '$' || c == '_';
    }
}
