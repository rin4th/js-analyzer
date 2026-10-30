package jsanalyzer.engine;

import jsanalyzer.model.AjaxFinding;
import jsanalyzer.model.AnalysisResult;
import jsanalyzer.model.EndpointFinding;
import jsanalyzer.model.FunctionFinding;
import jsanalyzer.model.SensitiveFinding;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Heuristic JavaScript analyzer. Mirrors the analyses of the js-extractor
 * project: endpoints, sensitive keyword hits, Ajax/XHR calls and parameters,
 * action-named functions with their source ranges, and potential DOM XSS
 * source-to-sink flows. Everything is static analysis; source is never run.
 */
public final class Analyzer {

    public static final List<String> SENSITIVE_KEYWORDS = List.of(
            "api_key", "token", "secret", "admin", "password", "bearer", "auth");

    public static final List<String> INTERESTING_ACTIONS = List.of(
            "upload", "delete", "rename", "admin", "execute", "create");

    private static final Pattern SERVER_SCRIPT = Pattern.compile(
            "\\.(?:aspx?|ashx|php|jsp|cgi)(?:[/?#]|$)", Pattern.CASE_INSENSITIVE);
    private static final Pattern API_PATH = Pattern.compile(
            "(?:^|/)api(?:/v\\d+(?:\\.\\d+)?)?(?=/|[?#]|$)", Pattern.CASE_INSENSITIVE);
    private static final Pattern ABSOLUTE = Pattern.compile(
            "^(?:https?:)?//[^/\\s]+", Pattern.CASE_INSENSITIVE);
    private static final Pattern QUERY_KEY = Pattern.compile("[?&]([^=&?#\\s]+)=");

    private Analyzer() {
    }

    public static AnalysisResult analyze(String source) {
        long started = System.nanoTime();
        String src = source == null ? "" : source;
        boolean debug = System.getenv("JSANALYZER_DEBUG") != null;
        long stage = System.nanoTime();
        JsLexer.Result lexed = JsLexer.lex(src);
        List<Token> tokens = lexed.tokens();
        if (debug) {
            System.err.println("lex: " + (System.nanoTime() - stage) / 1_000_000 + " ms, tokens="
                    + tokens.size());
            stage = System.nanoTime();
        }
        Map<String, Binding> bindings = collectBindings(tokens, src);

        List<EndpointFinding> endpoints = extractEndpoints(tokens);
        List<SensitiveFinding> sensitive = extractSensitive(tokens, src);
        List<AjaxFinding> ajax = extractAjax(tokens, src, bindings);
        if (debug) {
            System.err.println("bindings/endpoints/secrets/ajax: "
                    + (System.nanoTime() - stage) / 1_000_000 + " ms");
            stage = System.nanoTime();
        }
        Set<String> endpointValues = new HashSet<>();
        Map<String, Set<String>> inferredMethods = new HashMap<>();
        for (AjaxFinding call : ajax) {
            String url = call.url();
            if (!isEndpoint(url) || call.method() == null || call.method().isBlank()) {
                continue;
            }
            inferredMethods.computeIfAbsent(url, key -> new LinkedHashSet<>()).add(call.method());
        }
        List<EndpointFinding> allEndpoints = new ArrayList<>();
        for (EndpointFinding endpoint : endpoints) {
            endpointValues.add(endpoint.value());
            allEndpoints.add(new EndpointFinding(endpoint.value(), endpoint.type(), endpoint.line(),
                    joinMethods(inferredMethods.get(endpoint.value()))));
        }
        for (AjaxFinding call : ajax) {
            String url = call.url();
            if (!isEndpoint(url) || !endpointValues.add(url)) {
                continue;
            }
            allEndpoints.add(new EndpointFinding(url, endpointType(url), call.line(),
                    joinMethods(inferredMethods.get(url))));
        }
        allEndpoints.sort((a, b) -> a.line() != b.line()
                ? Integer.compare(a.line(), b.line())
                : a.value().compareTo(b.value()));

        List<FunctionFinding> functions = extractFunctions(tokens, src);
        if (debug) {
            System.err.println("functions: " + (System.nanoTime() - stage) / 1_000_000 + " ms");
            stage = System.nanoTime();
        }
        List<jsanalyzer.model.DomXssFinding> domXss = DomXssAnalyzer.analyze(tokens, src);
        if (debug) {
            System.err.println("dom: " + (System.nanoTime() - stage) / 1_000_000 + " ms");
        }

        long durationMs = Math.max(0, (System.nanoTime() - started) / 1_000_000L);
        String parseError = lexed.errors().isEmpty() ? findParseIssue(tokens) : lexed.errors().get(0);
        return new AnalysisResult(allEndpoints, sensitive, ajax, domXss, functions, parseError,
                countLines(src), src.getBytes(StandardCharsets.UTF_8).length, durationMs);
    }

    /** Cheap structural sanity check so the UI can flag heuristic-only results. */
    private static String findParseIssue(List<Token> tokens) {
        int parens = 0;
        int brackets = 0;
        int braces = 0;
        for (Token token : tokens) {
            if (token.kind != Token.Kind.PUNCT) {
                continue;
            }
            switch (token.text) {
                case "(":
                    parens++;
                    break;
                case ")":
                    parens--;
                    break;
                case "[":
                    brackets++;
                    break;
                case "]":
                    brackets--;
                    break;
                case "{":
                    braces++;
                    break;
                case "}":
                    braces--;
                    break;
                default:
                    break;
            }
            if (parens < 0 || brackets < 0 || braces < 0) {
                return "Unbalanced brackets near line " + token.line;
            }
        }
        if (parens != 0 || brackets != 0 || braces != 0) {
            return "Unbalanced brackets at end of file";
        }
        for (int i = 0; i < tokens.size(); i++) {
            Token token = tokens.get(i);
            if (!token.isPunct("=") || i + 1 >= tokens.size()) {
                continue;
            }
            Token next = tokens.get(i + 1);
            if (next.isPunct(";") || next.isPunct(")") || next.isPunct("}") || next.isPunct(",")) {
                return "Unexpected token '" + next.text + "' at line " + next.line;
            }
        }
        return null;
    }

    private static int countLines(String source) {
        if (source.isEmpty()) {
            return 0;
        }
        int lines = 1;
        for (int i = 0; i < source.length(); i++) {
            if (source.charAt(i) == '\n') {
                lines++;
            }
        }
        return lines;
    }

    // ------------------------------------------------------------------
    // Bindings
    // ------------------------------------------------------------------

    private static Map<String, Binding> collectBindings(List<Token> tokens, String source) {
        Map<String, Binding> bindings = new LinkedHashMap<>();
        int size = tokens.size();
        for (int i = 0; i < size; i++) {
            Token token = tokens.get(i);
            if (token.kind == Token.Kind.NAME && isDeclarationKeyword(token.text)) {
                int j = i + 1;
                while (j < size) {
                    Token nameToken = tokens.get(j);
                    if (nameToken.kind != Token.Kind.NAME) {
                        break;
                    }
                    if (j + 1 < size && tokens.get(j + 1).isPunct("=")) {
                        int end = Tokens.expressionEnd(tokens, j + 2);
                        if (end > j + 2) {
                            putBinding(bindings, tokens, source, nameToken.text, j + 2, Math.min(end, size));
                        }
                        j = end;
                        if (j < size && tokens.get(j).isPunct(",")) {
                            j++;
                            continue;
                        }
                    }
                    break;
                }
            }
            if (token.kind == Token.Kind.NAME && i + 2 < size && tokens.get(i + 1).isPunct("=")
                    && tokens.get(i + 1).text.equals("=")) {
                int end = Tokens.expressionEnd(tokens, i + 2);
                if (end > i + 2) {
                    putBinding(bindings, tokens, source, token.text, i + 2, Math.min(end, size));
                }
            }
        }
        return bindings;
    }

    private static void putBinding(Map<String, Binding> bindings, List<Token> tokens, String source,
                                   String name, int from, int to) {
        if (name == null || name.isEmpty() || from < 0 || from >= to) {
            return;
        }
        bindings.put(name, new Binding(from, to, Tokens.slice(source, tokens, from, to)));
    }

    private static boolean isDeclarationKeyword(String text) {
        return text.equals("const") || text.equals("let") || text.equals("var");
    }

    // ------------------------------------------------------------------
    // Endpoints
    // ------------------------------------------------------------------

    private static List<EndpointFinding> extractEndpoints(List<Token> tokens) {
        List<EndpointFinding> findings = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (Token token : tokens) {
            String value = null;
            if (token.kind == Token.Kind.STRING) {
                value = token.value;
            } else if (token.kind == Token.Kind.TEMPLATE) {
                value = templateValue(token, Map.of(), 0);
            }
            if (value == null) {
                continue;
            }
            String candidate = value.trim();
            if (!isEndpoint(candidate) || !seen.add(candidate)) {
                continue;
            }
            findings.add(new EndpointFinding(candidate, endpointType(candidate), token.line));
        }
        return findings;
    }

    /** "GET" / "GET, POST" / "" for endpoints with no method in the source. */
    private static String joinMethods(Set<String> methods) {
        if (methods == null || methods.isEmpty()) {
            return "";
        }
        List<String> sorted = new ArrayList<>(methods);
        sorted.sort(String::compareTo);
        return String.join(", ", sorted);
    }

    static boolean isEndpoint(String value) {
        if (value == null) {
            return false;
        }
        String candidate = value.trim();
        if (candidate.isEmpty() || candidate.contains("\n") || candidate.contains("\r")
                || candidate.length() > 2048) {
            return false;
        }
        return ABSOLUTE.matcher(candidate).find()
                || candidate.matches("^(?:\\.\\./|\\./|/(?!/))[^\\s]+.*")
                || SERVER_SCRIPT.matcher(candidate).find()
                || API_PATH.matcher(candidate).find();
    }

    static String endpointType(String value) {
        String candidate = value == null ? "" : value.trim();
        if (ABSOLUTE.matcher(candidate).find()) {
            return "absolute";
        }
        if (SERVER_SCRIPT.matcher(candidate).find()) {
            return "server-script";
        }
        if (API_PATH.matcher(candidate).find()) {
            return "api";
        }
        return "relative";
    }

    // ------------------------------------------------------------------
    // String resolution
    // ------------------------------------------------------------------

    static String templateValue(Token token, Map<String, Binding> bindings, int depth) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < token.quasis.size(); i++) {
            builder.append(token.quasis.get(i));
            if (i < token.expressions.size()) {
                String expression = token.expressions.get(i);
                String resolved = resolveExpression(expression, bindings, depth + 1);
                String display = resolved != null && !resolved.isBlank() ? resolved : expression.trim();
                builder.append("${").append(display).append('}');
            }
        }
        return builder.toString();
    }

    static String resolveExpression(String expression, Map<String, Binding> bindings, int depth) {
        if (expression == null || expression.isBlank() || depth > 8) {
            return "";
        }
        List<Token> tokens = JsLexer.lex(expression).tokens();
        return resolveRange(tokens, 0, tokens.size(), expression, bindings, depth);
    }

    /**
     * Resolves a token range that is expected to be a string expression:
     * literals, templates, identifiers bound to a literal, and {@code +}
     * concatenations. Anything else falls back to the source text.
     */
    static String resolveRange(List<Token> tokens, int from, int to, String source,
                               Map<String, Binding> bindings, int depth) {
        if (from < 0 || from >= to || to > tokens.size() || depth > 8) {
            return "";
        }
        int start = from;
        int end = to;
        // unwrap parentheses
        while (start < end && tokens.get(start).isPunct("(")
                && Tokens.matching(tokens, start) == end - 1) {
            start++;
            end--;
        }
        if (start >= end) {
            return "";
        }
        // split top-level concatenation
        List<int[]> parts = new ArrayList<>();
        int partStart = start;
        int nesting = 0;
        for (int i = start; i < end; i++) {
            Token token = tokens.get(i);
            if (token.kind == Token.Kind.PUNCT) {
                switch (token.text) {
                    case "(":
                    case "[":
                    case "{":
                        nesting++;
                        break;
                    case ")":
                    case "]":
                    case "}":
                        nesting = Math.max(0, nesting - 1);
                        break;
                    case "+":
                        if (nesting == 0 && i > partStart) {
                            parts.add(new int[]{partStart, i});
                            partStart = i + 1;
                        }
                        break;
                    default:
                        break;
                }
            }
        }
        if (!parts.isEmpty() && partStart < end) {
            parts.add(new int[]{partStart, end});
            StringBuilder builder = new StringBuilder();
            for (int[] part : parts) {
                builder.append(resolveRange(tokens, part[0], part[1], source, bindings, depth + 1));
            }
            return builder.toString();
        }
        // Prefer a statically known fallback: url ?? '/api/x' or base || '/api/x'.
        if (hasTopLevelFallback(tokens, start, end)) {
            List<int[]> alternatives = new ArrayList<>();
            int alternativeStart = start;
            int alternativeNesting = 0;
            for (int i = start; i < end; i++) {
                Token token = tokens.get(i);
                if (token.kind == Token.Kind.PUNCT) {
                    switch (token.text) {
                        case "(":
                        case "[":
                        case "{":
                            alternativeNesting++;
                            break;
                        case ")":
                        case "]":
                        case "}":
                            alternativeNesting = Math.max(0, alternativeNesting - 1);
                            break;
                        case "??":
                        case "||":
                            if (alternativeNesting == 0) {
                                alternatives.add(new int[]{alternativeStart, i});
                                alternativeStart = i + 1;
                            }
                            break;
                        default:
                            break;
                    }
                }
            }
            if (!alternatives.isEmpty() && alternativeStart < end) {
                alternatives.add(new int[]{alternativeStart, end});
                String firstResolved = null;
                for (int[] part : alternatives) {
                    int[] trimmed = part;
                    while (trimmed[0] < trimmed[1]
                            && (tokens.get(trimmed[0]).isPunct("(")
                            || tokens.get(trimmed[0]).kind == Token.Kind.PUNCT)) {
                        trimmed = new int[]{trimmed[0] + 1, trimmed[1]};
                    }
                    if (trimmed[0] < trimmed[1] && trimmed[1] - trimmed[0] == 1
                            && (tokens.get(trimmed[0]).kind == Token.Kind.STRING
                            || tokens.get(trimmed[0]).kind == Token.Kind.TEMPLATE)) {
                        return resolveRange(tokens, trimmed[0], trimmed[1], source, bindings, depth + 1);
                    }
                    if (firstResolved == null) {
                        firstResolved = resolveRange(tokens, trimmed[0], trimmed[1], source, bindings,
                                depth + 1);
                    }
                }
                if (firstResolved != null && !firstResolved.isBlank()) {
                    return firstResolved;
                }
            }
        }
        if (end - start == 1) {
            Token token = tokens.get(start);
            if (token.kind == Token.Kind.STRING) {
                return token.value;
            }
            if (token.kind == Token.Kind.TEMPLATE) {
                return templateValue(token, bindings, depth + 1);
            }
            if (token.kind == Token.Kind.NAME) {
                Binding binding = bindings.get(token.text);
                if (binding != null && depth < 8 && !binding.text.isBlank()
                        && !binding.text.equals(token.text)) {
                    // Resolve the bound expression from its own text: the token
                    // indices belong to the file-wide list, not to this one.
                    String resolved = resolveExpression(binding.text, bindings, depth + 1);
                    if (resolved != null && !resolved.isBlank()) {
                        return resolved;
                    }
                }
                return token.text;
            }
            return token.text;
        }
        return Tokens.compact(Tokens.slice(source, tokens, start, end));
    }

    private static boolean hasTopLevelFallback(List<Token> tokens, int from, int to) {
        int nesting = 0;
        for (int i = from; i < to; i++) {
            Token token = tokens.get(i);
            if (token.kind != Token.Kind.PUNCT) {
                continue;
            }
            switch (token.text) {
                case "(":
                case "[":
                case "{":
                    nesting++;
                    break;
                case ")":
                case "]":
                case "}":
                    nesting = Math.max(0, nesting - 1);
                    break;
                case "??":
                case "||":
                    if (nesting == 0) {
                        return true;
                    }
                    break;
                default:
                    break;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------
    // Sensitive findings
    // ------------------------------------------------------------------

    private static List<SensitiveFinding> extractSensitive(List<Token> tokens, String source) {
        List<SensitiveFinding> findings = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        int size = tokens.size();

        for (int i = 0; i < size; i++) {
            Token token = tokens.get(i);

            if (token.kind == Token.Kind.NAME && isDeclarationKeyword(token.text)) {
                int j = i + 1;
                while (j < size) {
                    Token nameToken = tokens.get(j);
                    if (nameToken.kind != Token.Kind.NAME) {
                        break;
                    }
                    if (j + 1 < size && tokens.get(j + 1).isPunct("=")) {
                        int end = Tokens.expressionEnd(tokens, j + 2);
                        String value = end > j + 2
                                ? Tokens.compact(Tokens.slice(source, tokens, j + 2, end))
                                : nameToken.text;
                        addSensitive(findings, seen, nameToken.text, value, nameToken.line,
                                "variable " + nameToken.text);
                        j = end;
                        if (j < size && tokens.get(j).isPunct(",")) {
                            j++;
                            continue;
                        }
                    }
                    break;
                }
                continue;
            }

            if (token.isPunct("=")) {
                int lhsEnd = i - 1;
                while (lhsEnd >= 0 && tokens.get(lhsEnd).kind != Token.Kind.NAME) {
                    lhsEnd--;
                }
                if (lhsEnd >= 0) {
                    int lhsStart = chainStart(tokens, lhsEnd);
                    String lhs = Tokens.compact(Tokens.slice(source, tokens, lhsStart, i));
                    int end = Tokens.expressionEnd(tokens, i + 1);
                    if (end > i + 1) {
                        String value = Tokens.compact(Tokens.slice(source, tokens, i + 1, end));
                        addSensitive(findings, seen, lhs, value, tokens.get(i).line, "assignment " + lhs);
                    }
                }
            }

            if ((token.kind == Token.Kind.NAME || token.kind == Token.Kind.STRING)
                    && i + 1 < size && tokens.get(i + 1).isPunct(":")
                    && i > 0 && (tokens.get(i - 1).isPunct("{") || tokens.get(i - 1).isPunct(","))) {
                String key = token.kind == Token.Kind.STRING ? token.value : token.text;
                int end = Tokens.expressionEnd(tokens, i + 2);
                if (end > i + 2) {
                    String value = Tokens.compact(Tokens.slice(source, tokens, i + 2, end));
                    addSensitive(findings, seen, key, value, token.line, "property " + key);
                }
            }

            if (token.kind == Token.Kind.STRING) {
                addSensitive(findings, seen, token.value, token.value, token.line, "string literal");
            } else if (token.kind == Token.Kind.TEMPLATE) {
                for (String quasi : token.quasis) {
                    addSensitive(findings, seen, quasi, quasi, token.line, "template string");
                }
            }
        }

        findings.sort((a, b) -> a.line() != b.line()
                ? Integer.compare(a.line(), b.line())
                : a.keyword().compareTo(b.keyword()));
        return findings;
    }

    private static void addSensitive(List<SensitiveFinding> findings, Set<String> seen,
                                     String matchText, String value, int line, String context) {
        for (String keyword : matchedSensitiveKeywords(matchText)) {
            String display = Tokens.compact(value);
            String key = keyword + "|" + display + "|" + line + "|" + context;
            if (seen.add(key)) {
                findings.add(new SensitiveFinding(keyword, display, line, context));
            }
        }
    }

    static List<String> matchedSensitiveKeywords(String value) {
        String text = String.valueOf(value == null ? "" : value).toLowerCase(Locale.ROOT);
        String compactText = text.replace("-", "").replace("_", "");
        List<String> matched = new ArrayList<>();
        for (String keyword : SENSITIVE_KEYWORDS) {
            boolean hit = keyword.equals("api_key") ? compactText.contains("apikey") : text.contains(keyword);
            if (hit) {
                matched.add(keyword);
            }
        }
        return matched;
    }

    static String matchedAction(String name) {
        String lower = String.valueOf(name == null ? "" : name).toLowerCase(Locale.ROOT);
        for (String action : INTERESTING_ACTIONS) {
            if (lower.contains(action)) {
                return action;
            }
        }
        return null;
    }

    private static int chainStart(List<Token> tokens, int nameIndex) {
        int start = nameIndex;
        while (start >= 2) {
            Token dot = tokens.get(start - 1);
            Token object = tokens.get(start - 2);
            if ((dot.isPunct(".") || dot.isPunct("?.")) && object.kind == Token.Kind.NAME) {
                start -= 2;
            } else {
                break;
            }
        }
        return start;
    }

    // ------------------------------------------------------------------
    // Ajax extraction
    // ------------------------------------------------------------------

    private static List<AjaxFinding> extractAjax(List<Token> tokens, String source,
                                                 Map<String, Binding> bindings) {
        Map<String, Set<String>> formData = new LinkedHashMap<>();
        Set<String> xhrVariables = new LinkedHashSet<>();
        int size = tokens.size();

        for (int i = 0; i < size; i++) {
            Token token = tokens.get(i);
            if (token.kind != Token.Kind.NAME || i + 1 >= size || !tokens.get(i + 1).isPunct("=")) {
                continue;
            }
            if (i + 2 < size && tokens.get(i + 2).isName("new")
                    && i + 3 < size && tokens.get(i + 3).kind == Token.Kind.NAME) {
                String type = tokens.get(i + 3).text;
                if (type.equals("FormData")) {
                    formData.put(token.text, new LinkedHashSet<>());
                } else if (type.equals("XMLHttpRequest")) {
                    xhrVariables.add(token.text);
                }
            }
        }

        for (int i = 0; i + 3 < size; i++) {
            Token token = tokens.get(i);
            String variable = token.text;
            if (token.kind != Token.Kind.NAME || !formData.containsKey(variable)) {
                continue;
            }
            if (!tokens.get(i + 1).isPunct(".") || !tokens.get(i + 2).kind.equals(Token.Kind.NAME)) {
                continue;
            }
            String method = tokens.get(i + 2).text;
            if (!method.equals("append") && !method.equals("set")) {
                continue;
            }
            int paren = i + 3;
            if (!tokens.get(paren).isPunct("(")) {
                continue;
            }
            List<int[]> args = Tokens.splitArguments(tokens, paren);
            if (args.isEmpty()) {
                continue;
            }
            String field = resolveRange(tokens, args.get(0)[0], args.get(0)[1], source, bindings, 0);
            if (!field.isBlank()) {
                formData.get(variable).add(field);
            }
        }

        List<AjaxFinding> calls = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            Token token = tokens.get(i);
            if (token.kind != Token.Kind.NAME) {
                continue;
            }

            // fetch(...)
            if (token.text.equals("fetch") && i + 1 < size && tokens.get(i + 1).isPunct("(")
                    && !(i > 0 && tokens.get(i - 1).isName("function"))) {
                AjaxFinding call = fromFetch(tokens, source, bindings, formData, i);
                if (call != null) {
                    calls.add(call);
                }
                continue;
            }

            // $.ajax(...) / jQuery.ajax(...)
            if (token.text.equals("ajax") && i + 1 < size && tokens.get(i + 1).isPunct("(")
                    && i >= 2 && tokens.get(i - 1).isPunct(".")
                    && (tokens.get(i - 2).isName("$") || tokens.get(i - 2).isName("jQuery"))) {
                AjaxFinding call = fromJquery(tokens, source, bindings, formData, i);
                if (call != null) {
                    calls.add(call);
                }
                continue;
            }

            // xhr.open(...)
            if (xhrVariables.contains(token.text) && i + 3 < size
                    && tokens.get(i + 1).isPunct(".") && tokens.get(i + 2).isName("open")
                    && tokens.get(i + 3).isPunct("(")) {
                AjaxFinding call = fromXhr(tokens, source, bindings, formData, xhrVariables, i);
                if (call != null) {
                    calls.add(call);
                }
            }
        }

        calls.sort((a, b) -> Integer.compare(a.line(), b.line()));
        return calls;
    }

    private static AjaxFinding fromFetch(List<Token> tokens, String source,
                                         Map<String, Binding> bindings,
                                         Map<String, Set<String>> formData, int index) {
        int paren = index + 1;
        List<int[]> args = Tokens.splitArguments(tokens, paren);
        if (args.isEmpty()) {
            return null;
        }
        String url = resolveRange(tokens, args.get(0)[0], args.get(0)[1], source, bindings, 0);
        if (looksLikeUrlValue(url)) {
            // analyzed below
        } else {
            return null;
        }
        String method = "GET";
        int[] bodyRange = null;
        if (args.size() > 1) {
            int[] options = args.get(1);
            int[] methodRange = objectProperty(tokens, options[0], options[1], "method", bindings);
            if (methodRange != null) {
                String resolved = resolveRange(tokens, methodRange[0], methodRange[1], source, bindings, 0);
                if (!resolved.isBlank()) {
                    method = resolved.toUpperCase(Locale.ROOT);
                }
            }
            bodyRange = objectProperty(tokens, options[0], options[1], "body", bindings);
        }
        List<String> parameters = parametersFor(tokens, source, bindings, formData, bodyRange, url);
        return new AjaxFinding("fetch", Tokens.compact(url), method, parameters, tokens.get(index).line);
    }

    private static AjaxFinding fromJquery(List<Token> tokens, String source,
                                          Map<String, Binding> bindings,
                                          Map<String, Set<String>> formData, int index) {
        int paren = index + 1;
        List<int[]> args = Tokens.splitArguments(tokens, paren);
        if (args.isEmpty()) {
            return null;
        }
        int[] first = args.get(0);
        String url;
        int optionsIndex;
        if (startsWith(tokens, first[0], first[1], "{")) {
            optionsIndex = 0;
            int[] urlRange = objectProperty(tokens, first[0], first[1], "url", bindings);
            if (urlRange == null) {
                return null;
            }
            url = resolveRange(tokens, urlRange[0], urlRange[1], source, bindings, 0);
        } else {
            optionsIndex = 1;
            url = resolveRange(tokens, first[0], first[1], source, bindings, 0);
        }
        if (url.isBlank() || optionsIndex >= args.size()) {
            return null;
        }
        int[] options = args.get(optionsIndex);
        int[] methodRange = objectProperty(tokens, options[0], options[1], "method", bindings);
        if (methodRange == null) {
            methodRange = objectProperty(tokens, options[0], options[1], "type", bindings);
        }
        String method = "GET";
        if (methodRange != null) {
            String resolved = resolveRange(tokens, methodRange[0], methodRange[1], source, bindings, 0);
            if (!resolved.isBlank()) {
                method = resolved.toUpperCase(Locale.ROOT);
            }
        }
        int[] dataRange = objectProperty(tokens, options[0], options[1], "data", bindings);
        if (dataRange == null) {
            dataRange = objectProperty(tokens, options[0], options[1], "body", bindings);
        }
        List<String> parameters = parametersFor(tokens, source, bindings, formData, dataRange, url);
        return new AjaxFinding("jquery.ajax", Tokens.compact(url), method, parameters,
                tokens.get(index).line);
    }

    private static AjaxFinding fromXhr(List<Token> tokens, String source,
                                       Map<String, Binding> bindings,
                                       Map<String, Set<String>> formData,
                                       Set<String> xhrVariables, int index) {
        int paren = index + 3;
        List<int[]> args = Tokens.splitArguments(tokens, paren);
        if (args.size() < 2) {
            return null;
        }
        String method = resolveRange(tokens, args.get(0)[0], args.get(0)[1], source, bindings, 0);
        String url = resolveRange(tokens, args.get(1)[0], args.get(1)[1], source, bindings, 0);
        if (url.isBlank()) {
            return null;
        }
        int openClose = Tokens.matching(tokens, paren);
        int[] bodyRange = null;
        int size = tokens.size();
        String variable = tokens.get(index).text;
        for (int i = Math.max(0, openClose); i < size; i++) {
            Token token = tokens.get(i);
            if (token.kind != Token.Kind.NAME || !token.text.equals(variable)) {
                continue;
            }
            if (i + 3 < size && tokens.get(i + 1).isPunct(".") && tokens.get(i + 2).isName("open")) {
                break;
            }
            if (i + 3 < size && tokens.get(i + 1).isPunct(".") && tokens.get(i + 2).isName("send")
                    && tokens.get(i + 3).isPunct("(")) {
                List<int[]> sendArgs = Tokens.splitArguments(tokens, i + 3);
                if (!sendArgs.isEmpty() && !Tokens.isBlank(sendArgs.get(0)[0], sendArgs.get(0)[1])) {
                    bodyRange = sendArgs.get(0);
                }
                break;
            }
        }
        LinkedHashSet<String> parameters = new LinkedHashSet<>();
        addQueryKeys(url, parameters);
        if (bodyRange != null) {
            collectKeys(tokens, source, bindings, formData, bodyRange[0], bodyRange[1], parameters, 0);
        }
        return new AjaxFinding("XMLHttpRequest", Tokens.compact(url),
                Tokens.compact(method.isBlank() ? "GET" : method.toUpperCase(Locale.ROOT)),
                new ArrayList<>(parameters), tokens.get(index).line);
    }

    /** Filters obvious non-URL expressions such as {@code new Foo(bar)} or bare numbers. */
    static boolean looksLikeUrlValue(String value) {
        if (value == null) {
            return false;
        }
        String candidate = value.trim();
        if (candidate.isEmpty() || candidate.length() > 2048) {
            return false;
        }
        if (candidate.matches("\\d+")) {
            return false;
        }
        if (candidate.startsWith("new ") || candidate.contains("=>")) {
            return false;
        }
        return true;
    }

    private static boolean startsWith(List<Token> tokens, int from, int to, String punct) {
        return from < to && tokens.get(from).isPunct(punct);
    }

    private static int[] objectProperty(List<Token> tokens, int from, int to, String wanted,
                                        Map<String, Binding> bindings) {
        int[] range = trimRange(tokens, from, to);
        if (range == null) {
            return null;
        }
        from = range[0];
        to = range[1];
        if (tokens.get(from).isPunct("(") && Tokens.matching(tokens, from) == to - 1) {
            return objectProperty(tokens, from + 1, to - 1, wanted, bindings);
        }
        if (to - from == 1 && tokens.get(from).kind == Token.Kind.NAME) {
            Binding binding = bindings.get(tokens.get(from).text);
            if (binding == null || !binding.fits(tokens.size())) {
                return null;
            }
            return objectProperty(tokens, binding.from, binding.to, wanted, bindings);
        }
        if (!tokens.get(from).isPunct("{")) {
            return null;
        }
        for (Map.Entry<String, int[]> property : objectProperties(tokens, from, to).entrySet()) {
            if (property.getKey().equalsIgnoreCase(wanted)) {
                return property.getValue();
            }
        }
        return null;
    }

    private static Map<String, int[]> objectProperties(List<Token> tokens, int from, int to) {
        Map<String, int[]> properties = new LinkedHashMap<>();
        int close = Tokens.matching(tokens, from);
        if (close > 0) {
            to = Math.min(to, close);
        }
        int i = from + 1;
        while (i < to) {
            Token token = tokens.get(i);
            if (token.isPunct(",")) {
                i++;
                continue;
            }
            if (token.isPunct("...")) {
                i = skipProperty(tokens, i + 1, to);
                continue;
            }
            String key = null;
            if (token.kind == Token.Kind.NAME) {
                key = token.text;
            } else if (token.kind == Token.Kind.STRING) {
                key = token.value;
            } else if (token.kind == Token.Kind.NUMBER) {
                key = token.text;
            }
            if (key != null && i + 1 < to && tokens.get(i + 1).isPunct(":")) {
                int valueStart = i + 2;
                int valueEnd = Math.min(to, Tokens.expressionEnd(tokens, valueStart));
                if (valueEnd <= valueStart) {
                    valueEnd = Math.min(to, valueStart + 1);
                }
                properties.putIfAbsent(key, new int[]{valueStart, valueEnd});
                i = valueEnd;
                if (i < to && tokens.get(i).isPunct(",")) {
                    i++;
                }
                continue;
            }
            i = skipProperty(tokens, i, to);
        }
        return properties;
    }

    private static int skipProperty(List<Token> tokens, int from, int to) {
        int depth = 0;
        for (int i = from; i < to; i++) {
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
                            return i;
                        }
                        break;
                    default:
                        break;
                }
            }
        }
        return to;
    }

    private static List<String> parametersFor(List<Token> tokens, String source,
                                              Map<String, Binding> bindings,
                                              Map<String, Set<String>> formData,
                                              int[] bodyRange, String url) {
        LinkedHashSet<String> parameters = new LinkedHashSet<>();
        if (bodyRange != null) {
            collectKeys(tokens, source, bindings, formData, bodyRange[0], bodyRange[1], parameters, 0);
        }
        addQueryKeys(url, parameters);
        return new ArrayList<>(parameters);
    }

    private static void collectKeys(List<Token> tokens, String source,
                                    Map<String, Binding> bindings,
                                    Map<String, Set<String>> formData,
                                    int from, int to, Set<String> output, int depth) {
        if (depth > 8) {
            return;
        }
        int[] range = trimRange(tokens, from, to);
        if (range == null) {
            return;
        }
        from = range[0];
        to = range[1];
        Token first = tokens.get(from);
        if (first.isPunct("(") && Tokens.matching(tokens, from) == to - 1) {
            collectKeys(tokens, source, bindings, formData, from + 1, to - 1, output, depth + 1);
            return;
        }
        if (to - from == 1 && first.kind == Token.Kind.NAME) {
            if (formData.containsKey(first.text)) {
                output.addAll(formData.get(first.text));
                return;
            }
            Binding binding = bindings.get(first.text);
            if (binding != null && binding.fits(tokens.size())) {
                collectKeys(tokens, source, bindings, formData, binding.from, binding.to, output, depth + 1);
            }
            return;
        }
        if (first.kind == Token.Kind.NAME) {
            int paren = -1;
            int cursor = from + 1;
            while (cursor + 1 < to && (tokens.get(cursor).isPunct(".")
                    || tokens.get(cursor).isPunct("?.")) && tokens.get(cursor + 1).kind == Token.Kind.NAME) {
                cursor += 2;
            }
            if (cursor < to && tokens.get(cursor).isPunct("(")) {
                paren = cursor;
            }
            if (paren > 0) {
                String callee = Tokens.slice(source, tokens, from, paren);
                String normalized = callee.replaceAll("\\s+", "");
                if (normalized.endsWith("JSON.stringify") || normalized.equals("URLSearchParams")
                        || normalized.endsWith("URLSearchParams")) {
                    List<int[]> args = Tokens.splitArguments(tokens, paren);
                    if (!args.isEmpty()) {
                        collectKeys(tokens, source, bindings, formData, args.get(0)[0], args.get(0)[1],
                                output, depth + 1);
                    }
                    return;
                }
            }
        }
        if (first.isPunct("{")) {
            Map<String, int[]> properties = objectProperties(tokens, from, to);
            for (Map.Entry<String, int[]> property : properties.entrySet()) {
                output.add(property.getKey());
                int valueFrom = property.getValue()[0];
                if (valueFrom < property.getValue()[1] && tokens.get(valueFrom).isPunct("{")) {
                    for (String nested : objectProperties(tokens, valueFrom, property.getValue()[1]).keySet()) {
                        output.add(nested);
                    }
                }
            }
            addSpreadKeys(tokens, source, bindings, formData, from, to, output, depth);
            return;
        }
        if (first.kind == Token.Kind.STRING) {
            addQueryKeys(first.value, output);
        }
    }

    private static void addSpreadKeys(List<Token> tokens, String source, Map<String, Binding> bindings,
                                      Map<String, Set<String>> formData, int from, int to,
                                      Set<String> output, int depth) {
        for (int i = from + 1; i < to; i++) {
            if (tokens.get(i).isPunct("...") && i + 1 < to) {
                int end = Math.min(to, Tokens.expressionEnd(tokens, i + 1));
                collectKeys(tokens, source, bindings, formData, i + 1, end > i + 1 ? end : i + 2, output,
                        depth + 1);
            }
        }
    }

    private static void addQueryKeys(String url, Set<String> output) {
        if (url == null) {
            return;
        }
        Matcher matcher = QUERY_KEY.matcher(url);
        while (matcher.find()) {
            output.add(decodeKey(matcher.group(1)));
        }
    }

    private static String decodeKey(String value) {
        try {
            return java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (RuntimeException ex) {
            return value;
        }
    }

    private static int[] trimRange(List<Token> tokens, int from, int to) {
        int start = from;
        int end = to;
        while (start < end) {
            Token token = tokens.get(start);
            if (token.isPunct(",") || token.isPunct(";")) {
                start++;
            } else {
                break;
            }
        }
        while (end > start) {
            Token token = tokens.get(end - 1);
            if (token.isPunct(",") || token.isPunct(";")) {
                end--;
            } else {
                break;
            }
        }
        return start >= end ? null : new int[]{start, end};
    }

    // ------------------------------------------------------------------
    // Interesting functions
    // ------------------------------------------------------------------

    private static List<FunctionFinding> extractFunctions(List<Token> tokens, String source) {
        List<FunctionFinding> findings = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        int size = tokens.size();

        for (int i = 0; i < size; i++) {
            Token token = tokens.get(i);

            if (token.kind == Token.Kind.NAME && token.text.equals("function")) {
                int nameIndex = i + 1;
                boolean generator = false;
                if (nameIndex < size && tokens.get(nameIndex).isPunct("*")) {
                    generator = true;
                    nameIndex++;
                }
                if (nameIndex + 1 >= size || tokens.get(nameIndex).kind != Token.Kind.NAME
                        || !tokens.get(nameIndex + 1).isPunct("(")) {
                    continue;
                }
                int paren = nameIndex + 1;
                int close = Tokens.matching(tokens, paren);
                if (close < 0) {
                    continue;
                }
                int endIndex = close;
                if (close + 1 < size && tokens.get(close + 1).isPunct("{")) {
                    int brace = Tokens.matching(tokens, close + 1);
                    if (brace > 0) {
                        endIndex = brace;
                    }
                }
                int startIndex = i;
                while (startIndex > 0 && tokens.get(startIndex - 1).kind == Token.Kind.NAME
                        && (tokens.get(startIndex - 1).text.equals("async")
                        || tokens.get(startIndex - 1).text.equals("export")
                        || tokens.get(startIndex - 1).text.equals("default"))) {
                    startIndex--;
                }
                String name = tokens.get(nameIndex).text;
                addFunction(findings, seen, name, tokens, source, startIndex, paren + 1, close, endIndex,
                        generator || isAsyncModifier(tokens, startIndex));
                continue;
            }

            // name = function / name = (params) => / name = param =>
            if (token.kind == Token.Kind.NAME && i + 1 < size && tokens.get(i + 1).isPunct("=")) {
                int chain = chainStart(tokens, i);
                int rhs = i + 2;
                if (rhs >= size) {
                    continue;
                }
                int[] arrow = arrowAt(tokens, rhs);
                if (arrow != null) {
                    int endIndex = arrow[2];
                    int expressionBody = Tokens.expressionEnd(tokens, arrow[2]);
                    boolean block = arrow[2] < size && tokens.get(arrow[2]).isPunct("{");
                    if (block) {
                        int brace = Tokens.matching(tokens, arrow[2]);
                        if (brace > 0) {
                            endIndex = brace;
                        }
                    } else {
                        endIndex = Math.max(arrow[2], expressionBody) - 1;
                    }
                    if (endIndex + 1 < size && tokens.get(endIndex + 1).isPunct(";")) {
                        endIndex++;
                    }
                    int startIndex = chain;
                    if (startIndex > 0 && isDeclarationKeyword(tokens.get(startIndex - 1).text)) {
                        startIndex--;
                    }
                    String name = Tokens.compact(Tokens.slice(source, tokens, chain, i + 1), 200);
                    addFunction(findings, seen, name, tokens, source, startIndex, arrow[0], arrow[1],
                            endIndex, false);
                    continue;
                }
                int functionIndex = rhs;
                if (functionIndex < size && tokens.get(functionIndex).isName("async")) {
                    functionIndex++;
                }
                if (functionIndex < size && tokens.get(functionIndex).isName("function")) {
                    int nameIndex = functionIndex + 1;
                    if (nameIndex < size && tokens.get(nameIndex).isPunct("*")) {
                        nameIndex++;
                    }
                    int paren = -1;
                    if (nameIndex < size && tokens.get(nameIndex).isPunct("(")) {
                        paren = nameIndex;
                    } else if (nameIndex + 1 < size && tokens.get(nameIndex).kind == Token.Kind.NAME
                            && tokens.get(nameIndex + 1).isPunct("(")) {
                        paren = nameIndex + 1;
                    }
                    if (paren > 0) {
                        int close = Tokens.matching(tokens, paren);
                        if (close < 0) {
                            continue;
                        }
                        int endIndex = close;
                        if (close + 1 < size && tokens.get(close + 1).isPunct("{")) {
                            int brace = Tokens.matching(tokens, close + 1);
                            if (brace > 0) {
                                endIndex = brace;
                            }
                        }
                        if (endIndex + 1 < size && tokens.get(endIndex + 1).isPunct(";")) {
                            endIndex++;
                        }
                        int startIndex = chain;
                        if (startIndex > 0 && isDeclarationKeyword(tokens.get(startIndex - 1).text)) {
                            startIndex--;
                        }
                        String name = Tokens.compact(Tokens.slice(source, tokens, chain, i + 1), 200);
                        addFunction(findings, seen, name, tokens, source, startIndex, paren + 1, close,
                                endIndex, tokens.get(functionIndex - 1).isName("async"));
                    }
                }
                continue;
            }

            // object / class shorthand method: name(params) { ... }
            if (token.kind == Token.Kind.NAME && i + 1 < size && tokens.get(i + 1).isPunct("(")) {
                if (i == 0) {
                    continue;
                }
                Token previous = tokens.get(i - 1);
                boolean methodContext = previous.isPunct("{") || previous.isPunct(",")
                        || previous.isPunct(";") || previous.isPunct("}");
                if (!methodContext) {
                    continue;
                }
                int close = Tokens.matching(tokens, i + 1);
                if (close < 0 || close + 1 >= size || !tokens.get(close + 1).isPunct("{")) {
                    continue;
                }
                int brace = Tokens.matching(tokens, close + 1);
                if (brace < 0) {
                    continue;
                }
                int startIndex = i;
                boolean async = previous.isName("async");
                if (async && i >= 2) {
                    startIndex = i - 1;
                }
                addFunction(findings, seen, token.text, tokens, source, startIndex, i + 2, close, brace,
                        async);
                continue;
            }

            // object property arrow: name: (a) => ... / name: x => ...
            if (token.kind == Token.Kind.NAME && i + 1 < size && tokens.get(i + 1).isPunct(":")) {
                int[] arrow = arrowAt(tokens, i + 2);
                if (arrow == null) {
                    continue;
                }
                int endIndex;
                if (arrow[2] < size && tokens.get(arrow[2]).isPunct("{")) {
                    int brace = Tokens.matching(tokens, arrow[2]);
                    endIndex = brace > 0 ? brace : arrow[2];
                } else {
                    endIndex = Math.max(arrow[2], Tokens.expressionEnd(tokens, arrow[2])) - 1;
                }
                addFunction(findings, seen, token.text, tokens, source, i, arrow[0], arrow[1], endIndex,
                        false);
            }
        }

        findings.sort((a, b) -> a.line() != b.line()
                ? Integer.compare(a.line(), b.line())
                : a.name().compareTo(b.name()));
        return findings;
    }

    private static boolean isAsyncModifier(List<Token> tokens, int startIndex) {
        return startIndex < tokens.size() && tokens.get(startIndex).isName("async");
    }

    /** Returns {@code [parenOpen, parenClose, bodyStart]} for an arrow function starting at {@code index}. */
    private static int[] arrowAt(List<Token> tokens, int index) {
        if (index >= tokens.size()) {
            return null;
        }
        Token token = tokens.get(index);
        if (token.kind == Token.Kind.NAME && index + 1 < tokens.size()
                && tokens.get(index + 1).isPunct("=>")) {
            return new int[]{index, index + 1, index + 2};
        }
        if (token.kind == Token.Kind.NAME && token.text.equals("async") && index + 1 < tokens.size()) {
            return arrowAt(tokens, index + 1);
        }
        if (token.isPunct("(")) {
            int close = Tokens.matching(tokens, index);
            if (close > 0 && close + 1 < tokens.size() && tokens.get(close + 1).isPunct("=>")) {
                return new int[]{index + 1, close, close + 2};
            }
        }
        return null;
    }

    private static void addFunction(List<FunctionFinding> findings, Set<String> seen, String name,
                                    List<Token> tokens, String source, int startIndex, int parenOpen,
                                    int parenClose, int endIndex, boolean async) {
        if (name == null || name.isBlank()) {
            return;
        }
        String action = matchedAction(name);
        if (action == null) {
            return;
        }
        int safeStart = Math.max(0, Math.min(startIndex, tokens.size() - 1));
        int safeEnd = Math.max(safeStart, Math.min(endIndex, tokens.size() - 1));
        Token startToken = tokens.get(safeStart);
        Token endToken = tokens.get(safeEnd);
        int line = startToken.line;
        String key = name + "|" + line;
        if (!seen.add(key)) {
            return;
        }
        String params = parenClose > parenOpen
                ? Tokens.compact(Tokens.slice(source, tokens, parenOpen, parenClose), 200)
                : "";
        String signature = Tokens.compact((async ? "async " : "") + name + "(" + params + ")", 200);
        findings.add(new FunctionFinding(name, action, line, signature, startToken.start, endToken.end));
    }
}
