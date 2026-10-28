package jsanalyzer.engine;

import jsanalyzer.model.DomXssFinding;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Lightweight DOM XSS dataflow analyzer. It tracks browser-controlled sources
 * through simple assignments, aliases, concatenations and templates into
 * dangerous HTML / script sinks, with a few nested calls recovered by hand.
 * Results are leads for manual validation, not confirmed vulnerabilities.
 */
public final class DomXssAnalyzer {

    private static final Map<String, String> HTML_PROPERTIES = Map.of(
            "innerhtml", "innerHTML",
            "outerhtml", "outerHTML",
            "srcdoc", "srcdoc");

    private static final Set<String> JQUERY_HTML_METHODS = Set.of(
            "html", "append", "prepend", "before", "after", "replacewith");

    private static final Set<String> PASSTHROUGH_METHODS = Set.of(
            "slice", "substring", "substr", "replace", "replaceall", "trim", "trimstart",
            "trimend", "tolowercase", "touppercase", "tostring", "concat", "normalize",
            "get", "getall", "decode", "atob", "btoa", "parse", "stringify");

    /** Interprocedural propagation is expensive; skip it on very large bundles. */
    private static final int PROPAGATION_FILE_LIMIT = 500_000;
    private static final int PROPAGATION_BODY_LIMIT = 20_000;

    private static final Pattern SOURCE_PATTERN = Pattern.compile(
            "^(?:(?:window|self)\\.)?location\\.(?:hash|search|href|pathname|origin)$"
                    + "|^(?:(?:window|self)\\.)?document\\.(?:url|documenturi|referrer|cookie|location)$"
                    + "|^(?:(?:window|self)\\.)?window\\.name$|^(?:window\\.)?name$"
                    + "|^history\\.state$"
                    + "|^(?:event|evt|messageevent|message|e)\\.data$"
                    + "|^(?:html|body|document\\.body|document\\.documentelement)$"
                    + "|^(?:document|window)\\.location$"
                    + "|^(?:localstorage|sessionstorage)\\.getitem\\(.*\\)$",
            Pattern.CASE_INSENSITIVE);

    private DomXssAnalyzer() {
    }

    // ------------------------------------------------------------------
    // Flow model
    // ------------------------------------------------------------------

    static final class Flow {
        final LinkedHashMap<String, List<String>> traces = new LinkedHashMap<>();
        boolean dynamic;
        boolean sanitized;

        static Flow constant() {
            return new Flow();
        }

        static Flow unresolved() {
            Flow flow = new Flow();
            flow.dynamic = true;
            return flow;
        }

        static Flow source(String name) {
            Flow flow = new Flow();
            flow.dynamic = true;
            flow.traces.put(name, new ArrayList<>(List.of(name)));
            return flow;
        }

        Flow extend(String step) {
            Flow result = new Flow();
            result.dynamic = dynamic;
            result.sanitized = sanitized;
            for (Map.Entry<String, List<String>> entry : traces.entrySet()) {
                List<String> path = new ArrayList<>(entry.getValue());
                if (path.isEmpty() || !path.get(path.size() - 1).equals(step)) {
                    path.add(step);
                }
                result.traces.put(entry.getKey(), path);
            }
            return result;
        }

        static Flow merge(Flow... flows) {
            Flow result = new Flow();
            for (Flow flow : flows) {
                if (flow == null) {
                    continue;
                }
                result.dynamic |= flow.dynamic;
                result.sanitized |= flow.sanitized;
                for (Map.Entry<String, List<String>> entry : flow.traces.entrySet()) {
                    List<String> current = result.traces.get(entry.getKey());
                    if (current == null || entry.getValue().size() < current.size()) {
                        result.traces.put(entry.getKey(), new ArrayList<>(entry.getValue()));
                    }
                }
            }
            return result;
        }
    }

    private static final class Context {
        final List<Token> tokens;
        final String source;
        final Map<String, Flow> environment = new LinkedHashMap<>();
        final Set<String> sanitizerObjects = new LinkedHashSet<>();
        final Map<String, DomXssFinding> findings = new LinkedHashMap<>();
        final Map<String, FunctionDef> functions = new LinkedHashMap<>();
        final Set<String> activeFunctions = new LinkedHashSet<>();
        int propagationBudget = 2_000_000;

        Context(List<Token> tokens, String source) {
            this.tokens = tokens;
            this.source = source;
        }
    }

    private static final class FunctionDef {
        final List<String> parameters;
        final int bodyFrom;
        final int bodyTo;

        FunctionDef(List<String> parameters, int bodyFrom, int bodyTo) {
            this.parameters = parameters;
            this.bodyFrom = bodyFrom;
            this.bodyTo = bodyTo;
        }
    }

    // ------------------------------------------------------------------
    // Entry point
    // ------------------------------------------------------------------

    public static List<DomXssFinding> analyze(List<Token> tokens, String source) {
        Context context = new Context(tokens, source);
        collectFunctions(context);
        scanStatements(context, 0, tokens.size());

        List<DomXssFinding> result = new ArrayList<>(context.findings.values());
        result.sort((a, b) -> a.line() != b.line()
                ? Integer.compare(a.line(), b.line())
                : a.sink().compareTo(b.sink()));
        return result;
    }

    private static void collectFunctions(Context context) {
        List<Token> tokens = context.tokens;
        for (int i = 0; i < tokens.size(); i++) {
            Token token = tokens.get(i);
            if (token.kind != Token.Kind.NAME || !token.text.equals("function")) {
                continue;
            }
            int nameIndex = i + 1;
            if (nameIndex < tokens.size() && tokens.get(nameIndex).isPunct("*")) {
                nameIndex++;
            }
            if (nameIndex >= tokens.size() || tokens.get(nameIndex).kind != Token.Kind.NAME) {
                continue;
            }
            int paren = nameIndex + 1;
            if (paren >= tokens.size() || !tokens.get(paren).isPunct("(")) {
                continue;
            }
            int close = Tokens.matching(tokens, paren);
            if (close < 0 || close + 1 >= tokens.size() || !tokens.get(close + 1).isPunct("{")) {
                continue;
            }
            int brace = Tokens.matching(tokens, close + 1);
            if (brace < 0) {
                continue;
            }
            List<String> parameters = new ArrayList<>();
            for (int[] range : Tokens.splitArguments(tokens, paren)) {
                if (range[1] > range[0] && tokens.get(range[0]).kind == Token.Kind.NAME) {
                    parameters.add(tokens.get(range[0]).text);
                } else {
                    parameters.add("");
                }
            }
            context.functions.put(tokens.get(nameIndex).text,
                    new FunctionDef(parameters, close + 2, brace));
        }
    }

    private static void scanStatements(Context context, int from, int to) {
        List<Token> tokens = context.tokens;
        boolean[] declarationEquals = new boolean[tokens.size()];
        for (int i = from; i < to; i++) {
            Token token = tokens.get(i);
            if (token.kind == Token.Kind.NAME
                    && (token.text.equals("const") || token.text.equals("let") || token.text.equals("var"))) {
                processDeclaration(context, i, declarationEquals);
            }
        }
        for (int i = from; i < to; i++) {
            Token token = tokens.get(i);
            if (token.isPunct("=") || token.isPunct("+=")) {
                if (!declarationEquals[i]) {
                    processAssignment(context, i);
                }
                continue;
            }
            if (token.isPunct("(") && i > 0) {
                Token previous = tokens.get(i - 1);
                if (previous.kind == Token.Kind.NAME || previous.isPunct(")") || previous.isPunct("]")) {
                    processCall(context, i);
                    propagateFunctionCall(context, i);
                }
                continue;
            }
            if (token.kind == Token.Kind.NAME && token.text.equalsIgnoreCase("dangerouslySetInnerHTML")
                    && i + 1 < tokens.size() && tokens.get(i + 1).isPunct(":")) {
                processReactHtml(context, i);
            }
        }
    }

    private static void propagateFunctionCall(Context context, int parenIndex) {
        List<Token> tokens = context.tokens;
        if (tokens.size() > PROPAGATION_FILE_LIMIT) {
            return;
        }
        int calleeIndex = parenIndex - 1;
        if (calleeIndex < 1) {
            return;
        }
        Token callee = tokens.get(calleeIndex);
        if (callee.kind != Token.Kind.NAME) {
            return;
        }
        if (calleeIndex >= 2 && (tokens.get(calleeIndex - 1).isPunct(".")
                || tokens.get(calleeIndex - 1).isPunct("?."))) {
            return;
        }
        FunctionDef function = context.functions.get(callee.text);
        if (function == null || context.activeFunctions.contains(callee.text)) {
            return;
        }
        int bodySize = function.bodyTo - function.bodyFrom;
        if (bodySize > PROPAGATION_BODY_LIMIT
                || bodySize > context.propagationBudget) {
            return;
        }
        context.propagationBudget -= bodySize;
        List<int[]> args = Tokens.splitArguments(tokens, parenIndex);
        Map<String, Flow> saved = new LinkedHashMap<>(context.environment);
        context.activeFunctions.add(callee.text);
        try {
            for (int i = 0; i < function.parameters.size(); i++) {
                String parameter = function.parameters.get(i);
                if (parameter.isEmpty()) {
                    continue;
                }
                Flow flow = i < args.size()
                        ? evaluate(tokens, args.get(i), context, 0)
                        : Flow.unresolved();
                context.environment.put(parameter, flow.extend(parameter));
            }
            scanStatements(context, function.bodyFrom, function.bodyTo);
        } finally {
            context.environment.clear();
            context.environment.putAll(saved);
            context.activeFunctions.remove(callee.text);
        }
    }

    // ------------------------------------------------------------------
    // Passes
    // ------------------------------------------------------------------

    private static void processDeclaration(Context context, int index, boolean[] declarationEquals) {
        List<Token> tokens = context.tokens;
        int j = index + 1;
        while (j < tokens.size()) {
            Token nameToken = tokens.get(j);
            if (nameToken.kind != Token.Kind.NAME) {
                return;
            }
            if (j + 1 < tokens.size() && tokens.get(j + 1).isPunct("=")) {
                declarationEquals[j + 1] = true;
                int end = Tokens.expressionEnd(tokens, j + 2);
                Flow flow = evaluate(tokens, j + 2, end, context, 0);
                context.environment.put(nameToken.text, flow.extend(nameToken.text));
                detectSanitizerPolicy(context, nameToken.text, j + 2, end);
                j = end;
                if (j < tokens.size() && tokens.get(j).isPunct(",")) {
                    j++;
                    continue;
                }
            }
            return;
        }
    }

    private static void processAssignment(Context context, int equalsIndex) {
        List<Token> tokens = context.tokens;
        int lhsEnd = equalsIndex - 1;
        if (lhsEnd < 1) {
            return;
        }
        Token lhsToken = tokens.get(lhsEnd);
        if (lhsToken.kind != Token.Kind.NAME) {
            return;
        }
        int start = chainStart(tokens, lhsEnd);
        int end = Tokens.expressionEnd(tokens, equalsIndex + 1);
        if (end <= equalsIndex + 1) {
            return;
        }
        Flow flow = evaluate(tokens, equalsIndex + 1, end, context, 0);
        boolean member = lhsEnd >= 2
                && (tokens.get(lhsEnd - 1).isPunct(".") || tokens.get(lhsEnd - 1).isPunct("?."));
        String property = lhsToken.text.toLowerCase(Locale.ROOT);
        if (member && HTML_PROPERTIES.containsKey(property)) {
            addFinding(context, HTML_PROPERTIES.get(property), flow, equalsIndex);
        } else {
            String name = chainText(tokens, start, equalsIndex);
            context.environment.put(name, flow.extend(name));
        }
    }

    private static void processCall(Context context, int parenIndex) {
        List<Token> tokens = context.tokens;
        int calleeEnd = parenIndex - 1;
        if (calleeEnd < 0) {
            return;
        }
        Token methodToken = tokens.get(calleeEnd);
        if (methodToken.kind != Token.Kind.NAME) {
            return;
        }
        String method = methodToken.text;
        String lower = method.toLowerCase(Locale.ROOT);
        List<int[]> args = Tokens.splitArguments(tokens, parenIndex);

        if (lower.equals("eval")) {
            addFinding(context, "eval", evaluate(tokens, arg(args, 0), context, 0), parenIndex);
            return;
        }
        if (method.equals("Function")) {
            addFinding(context, "Function constructor",
                    evaluate(tokens, arg(args, args.size() - 1), context, 0), parenIndex);
            return;
        }
        if (lower.equals("settimeout") || lower.equals("setinterval")) {
            int[] first = arg(args, 0);
            boolean functionArgument = first != null && first[0] < first[1]
                    && (tokens.get(first[0]).isName("function")
                    || tokens.get(first[0]).kind == Token.Kind.NAME
                    && tokens.get(first[0]).text.equals("async")
                    || tokens.get(first[0]).isPunct("(")
                    && Tokens.matching(tokens, first[0]) > 0
                    && tokens.get(Tokens.matching(tokens, first[0]) + 1).isPunct("=>")
                    || first[0] + 1 < first[1] && tokens.get(first[0] + 1).isPunct("=>"));
            if (!functionArgument) {
                addFinding(context, method, evaluate(tokens, first, context, 0), parenIndex);
            }
            return;
        }
        if (lower.equals("insertadjacenthtml")) {
            addFinding(context, "insertAdjacentHTML", evaluate(tokens, arg(args, 1), context, 0), parenIndex);
            return;
        }
        if (lower.equals("sethtmlunsafe") || lower.equals("createcontextualfragment")) {
            addFinding(context, method, evaluate(tokens, arg(args, 0), context, 0), parenIndex);
            return;
        }
        if (lower.equals("setattribute")) {
            String attribute = staticString(tokens, arg(args, 0));
            if (attribute != null) {
                String name = attribute.toLowerCase(Locale.ROOT);
                if (name.equals("srcdoc") || name.matches("^on[a-z]+$")) {
                    addFinding(context, "setAttribute(" + name + ")",
                            evaluate(tokens, arg(args, 1), context, 0), parenIndex);
                }
            }
            return;
        }
        if ((lower.equals("write") || lower.equals("writeln")) && receiverIsDocument(tokens, calleeEnd)) {
            Flow merged = Flow.constant();
            for (int[] range : args) {
                merged = Flow.merge(merged, evaluate(tokens, range, context, 0));
            }
            addFinding(context, "document." + method, merged, parenIndex);
            return;
        }
        if (lower.equals("execcommand")) {
            String command = staticString(tokens, arg(args, 0));
            if (command != null && command.equalsIgnoreCase("insertHTML")) {
                addFinding(context, "execCommand(insertHTML)",
                        evaluate(tokens, arg(args, 2), context, 0), parenIndex);
            }
            return;
        }
        if (JQUERY_HTML_METHODS.contains(lower) && isJqueryReceiver(tokens, calleeEnd)) {
            Flow merged = Flow.constant();
            for (int[] range : args) {
                merged = Flow.merge(merged, evaluate(tokens, range, context, 0));
            }
            String canonical = lower.equals("replacewith") ? "replaceWith" : lower;
            addFinding(context, "jQuery." + canonical, merged, parenIndex);
        }
    }

    private static void processReactHtml(Context context, int index) {
        List<Token> tokens = context.tokens;
        int valueStart = index + 2;
        int valueEnd = Tokens.expressionEnd(tokens, valueStart);
        if (valueEnd <= valueStart) {
            return;
        }
        if (!tokens.get(valueStart).isPunct("{")) {
            addFinding(context, "React.dangerouslySetInnerHTML",
                    evaluate(tokens, valueStart, valueEnd, context, 0), index);
            return;
        }
        int[] html = objectPropertyRange(tokens, valueStart, valueEnd, "__html");
        if (html == null) {
            return;
        }
        addFinding(context, "React.dangerouslySetInnerHTML",
                evaluate(tokens, html, context, 0), index);
    }

    private static void detectSanitizerPolicy(Context context, String name, int from, int to) {
        String chunk = Tokens.slice(context.source, context.tokens, from, to);
        if (!chunk.contains("createPolicy")) {
            return;
        }
        boolean sanitizes = chunk.contains("DOMPurify.sanitize") || chunk.contains("DOMPurify?.sanitize")
                || chunk.contains("new Sanitizer") || chunk.contains("Sanitizer(");
        boolean identity = Pattern.compile("createHTML\\s*:\\s*\\(?\\s*\\w+\\s*\\)?\\s*=>\\s*\\w+\\s*[}),]")
                .matcher(chunk).find();
        if (sanitizes && !identity) {
            context.sanitizerObjects.add(name);
        }
    }

    // ------------------------------------------------------------------
    // Expression evaluation
    // ------------------------------------------------------------------

    private static Flow evaluate(List<Token> tokens, int[] range, Context context, int depth) {
        if (range == null) {
            return Flow.constant();
        }
        return evaluate(tokens, range[0], range[1], context, depth);
    }

    private static Flow evaluate(List<Token> tokens, int from, int to, Context context, int depth) {
        if (depth > 20) {
            return Flow.unresolved();
        }
        int start = from;
        int end = to;
        while (start < end && tokens.get(start).isPunct("(")
                && Tokens.matching(tokens, start) == end - 1) {
            start++;
            end--;
        }
        if (start >= end) {
            return Flow.unresolved();
        }
        if (end - start == 1) {
            Token token = tokens.get(start);
            if (token.kind == Token.Kind.STRING || token.kind == Token.Kind.NUMBER
                    || token.kind == Token.Kind.REGEX) {
                return Flow.constant();
            }
            if (token.kind == Token.Kind.TEMPLATE) {
                Flow merged = token.expressions.isEmpty() ? Flow.constant() : Flow.unresolved();
                for (String expression : token.expressions) {
                    List<Token> sub = JsLexer.lex(expression).tokens();
                    merged = Flow.merge(merged, evaluate(sub, 0, sub.size(), context, depth + 1));
                }
                return merged;
            }
            if (token.kind == Token.Kind.NAME) {
                if (token.text.equals("location")) {
                    return Flow.source("location");
                }
                Flow known = context.environment.get(token.text);
                return known == null ? Flow.unresolved() : known;
            }
            return Flow.unresolved();
        }

        int topLevel = topLevelOperator(tokens, start, end);
        if (topLevel >= 0) {
            Flow left = evaluate(tokens, start, topLevel, context, depth + 1);
            Flow right = evaluate(tokens, topLevel + 1, end, context, depth + 1);
            return Flow.merge(left, right);
        }

        // call expression ending at the range end
        if (tokens.get(end - 1).isPunct(")")) {
            int open = Tokens.matchingBackwards(tokens, end - 1);
            if (open > start) {
                Flow call = evaluateCall(tokens, start, open, end - 1, context, depth);
                if (call != null) {
                    return call;
                }
            }
        }

        // member expression
        Token last = tokens.get(end - 1);
        if (last.kind == Token.Kind.NAME && end - 2 >= start
                && (tokens.get(end - 2).isPunct(".") || tokens.get(end - 2).isPunct("?."))) {
            int chain = chainStart(tokens, end - 1);
            String name = chainText(tokens, chain, end);
            if (SOURCE_PATTERN.matcher(name).matches()) {
                return Flow.source(name);
            }
            Flow known = context.environment.get(name);
            if (known != null) {
                return known;
            }
            return evaluate(tokens, chain, end - 2, context, depth + 1);
        }

        if (tokens.get(start).isPunct("{")) {
            Flow merged = Flow.constant();
            for (Map.Entry<String, int[]> property : objectProperties(tokens, start, end).entrySet()) {
                merged = Flow.merge(merged,
                        evaluate(tokens, property.getValue()[0], property.getValue()[1], context, depth + 1));
            }
            return merged;
        }

        return Flow.unresolved();
    }

    /** Evaluates a call whose opening parenthesis is at {@code open} and closing at {@code close}. */
    private static Flow evaluateCall(List<Token> tokens, int from, int open, int close, Context context,
                                     int depth) {
        int calleeEnd = open - 1;
        if (calleeEnd < 0 || calleeEnd >= tokens.size()) {
            return null;
        }
        Token calleeToken = tokens.get(calleeEnd);
        if (calleeToken.kind != Token.Kind.NAME) {
            return null;
        }
        String method = calleeToken.text;
        int dot = calleeEnd >= 1 && (tokens.get(calleeEnd - 1).isPunct(".")
                || tokens.get(calleeEnd - 1).isPunct("?.")) ? calleeEnd - 1 : -1;
        String calleeText = method;
        if (dot > 0) {
            int chain = chainStart(tokens, calleeEnd);
            calleeText = chainText(tokens, chain, calleeEnd + 1);
        }
        List<int[]> args = Tokens.splitArguments(tokens, open);
        List<Flow> argumentFlows = new ArrayList<>();
        for (int[] range : args) {
            argumentFlows.add(evaluate(tokens, range, context, depth + 1));
        }
        Flow merged = Flow.constant();
        for (Flow flow : argumentFlows) {
            merged = Flow.merge(merged, flow);
        }

        if (isSanitizerCall(calleeText, context)) {
            Flow sanitized = new Flow();
            sanitized.sanitized = true;
            return sanitized;
        }
        if (isBrowserSourceCall(calleeText)) {
            return Flow.source(calleeText);
        }
        if (dot > 0 && PASSTHROUGH_METHODS.contains(method.toLowerCase(Locale.ROOT))) {
            merged = Flow.merge(merged, evaluate(tokens, from, dot, context, depth + 1));
        }
        if (!merged.traces.isEmpty() || merged.dynamic) {
            return merged.extend(calleeText + "()");
        }
        return merged;
    }

    private static boolean isSanitizerCall(String calleeText, Context context) {
        String lower = calleeText.toLowerCase(Locale.ROOT);
        if (lower.endsWith("dompurify.sanitize")) {
            return true;
        }
        int dot = calleeText.lastIndexOf('.');
        if (dot <= 0) {
            return false;
        }
        String receiver = calleeText.substring(0, dot);
        String method = calleeText.substring(dot + 1).toLowerCase(Locale.ROOT);
        if (context.sanitizerObjects.contains(receiver)
                && (method.equals("sanitize") || method.equals("sanitizefor")
                || method.equals("createhtml") || method.equals("createhtmlunsafe"))) {
            return true;
        }
        return false;
    }

    private static boolean isBrowserSourceCall(String calleeText) {
        String lower = calleeText.toLowerCase(Locale.ROOT);
        return lower.equals("prompt") || lower.equals("window.prompt")
                || lower.equals("localstorage.getitem") || lower.equals("sessionstorage.getitem")
                || lower.equals("window.name");
    }

    private static int topLevelOperator(List<Token> tokens, int from, int to) {
        int depth = 0;
        for (int i = from; i < to; i++) {
            Token token = tokens.get(i);
            if (token.kind == Token.Kind.PUNCT) {
                switch (token.text) {
                    case "(":
                    case "[":
                    case "{":
                        depth++;
                        continue;
                    case ")":
                    case "]":
                    case "}":
                        depth = Math.max(0, depth - 1);
                        continue;
                    default:
                        break;
                }
                if (depth == 0 && isMergeOperator(token.text)) {
                    return i;
                }
            }
        }
        return -1;
    }

    private static boolean isMergeOperator(String text) {
        switch (text) {
            case "+":
            case "-":
            case "*":
            case "/":
            case "%":
            case "||":
            case "&&":
            case "??":
            case "|":
            case "&":
            case "^":
            case "?":
            case ":":
            case ",":
            case "==":
            case "===":
            case "!=":
            case "!==":
            case "<":
            case ">":
            case "<=":
            case ">=":
                return true;
            default:
                return false;
        }
    }

    // ------------------------------------------------------------------
    // Findings
    // ------------------------------------------------------------------

    private static void addFinding(Context context, String sink, Flow flow, int anchorIndex) {
        if (flow.traces.isEmpty() && (!flow.dynamic || flow.sanitized)) {
            return;
        }
        List<Token> tokens = context.tokens;
        int anchor = Math.max(0, Math.min(anchorIndex, tokens.size() - 1));
        int line = tokens.get(anchor).line;
        boolean tainted = !flow.traces.isEmpty();
        String source = tainted ? String.join(", ", flow.traces.keySet()) : "Unresolved dynamic value";
        String confidence = tainted ? "high" : "low";
        String severity = tainted ? "high" : "medium";
        List<String> path = new ArrayList<>();
        if (tainted) {
            path.addAll(flow.traces.values().iterator().next());
        }
        path.add(sink);
        int[] statement = statementRange(tokens, context.source, anchor);
        String evidence = Tokens.compact(context.source.substring(statement[0], statement[1]), 500);
        String key = tokens.get(anchor).start + "|" + sink;
        DomXssFinding finding = new DomXssFinding(sink, source, line, severity, confidence, evidence,
                path, statement[0], statement[1]);
        DomXssFinding current = context.findings.get(key);
        if (current == null || rank(finding.confidence()) > rank(current.confidence())) {
            context.findings.put(key, finding);
        }
    }

    private static int rank(String confidence) {
        return "high".equals(confidence) ? 3 : "medium".equals(confidence) ? 2 : 1;
    }

    private static int[] statementRange(List<Token> tokens, String source, int anchorIndex) {
        Token anchor = tokens.get(anchorIndex);
        int lineStart = source.lastIndexOf('\n', Math.max(0, anchor.start - 1)) + 1;
        while (lineStart < source.length() && Character.isWhitespace(source.charAt(lineStart))) {
            lineStart++;
        }
        int end = -1;
        int depth = 0;
        int limit = Math.min(tokens.size(), anchorIndex + 1000);
        for (int i = anchorIndex; i < limit; i++) {
            Token token = tokens.get(i);
            if (token.kind != Token.Kind.PUNCT) {
                continue;
            }
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
                        end = token.start;
                    } else {
                        depth--;
                    }
                    break;
                case ";":
                    if (depth == 0) {
                        end = token.end;
                    }
                    break;
                default:
                    break;
            }
            if (end >= 0) {
                break;
            }
        }
        if (end < 0) {
            int newline = source.indexOf('\n', anchor.end);
            end = newline < 0 ? source.length() : newline;
        }
        if (end <= lineStart) {
            end = Math.min(source.length(), anchor.end);
        }
        return new int[]{lineStart, end};
    }

    // ------------------------------------------------------------------
    // Token helpers
    // ------------------------------------------------------------------

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

    private static String chainText(List<Token> tokens, int from, int toExclusive) {
        StringBuilder builder = new StringBuilder();
        for (int i = from; i < Math.min(toExclusive, tokens.size()); i++) {
            builder.append(tokens.get(i).text);
        }
        return builder.toString();
    }

    private static int[] arg(List<int[]> arguments, int index) {
        return index >= 0 && index < arguments.size() ? arguments.get(index) : null;
    }

    private static String staticString(List<Token> tokens, int[] range) {
        if (range == null || range[1] - range[0] != 1) {
            return null;
        }
        Token token = tokens.get(range[0]);
        if (token.kind == Token.Kind.STRING) {
            return token.value;
        }
        if (token.kind == Token.Kind.TEMPLATE && token.expressions.isEmpty()) {
            return String.join("", token.quasis);
        }
        return null;
    }

    private static boolean receiverIsDocument(List<Token> tokens, int calleeEnd) {
        if (calleeEnd >= 2 && tokens.get(calleeEnd - 1).isPunct(".")
                && tokens.get(calleeEnd - 2).isName("document")) {
            return true;
        }
        return false;
    }

    private static boolean isJqueryReceiver(List<Token> tokens, int calleeEnd) {
        int from = Math.max(0, calleeEnd - 80);
        StringBuilder builder = new StringBuilder();
        for (int i = from; i <= calleeEnd; i++) {
            builder.append(tokens.get(i).text);
        }
        String text = builder.toString();
        return text.contains("$(") || text.contains("$.") || text.contains("jQuery(")
                || text.contains("jQuery.");
    }

    private static Map<String, int[]> objectProperties(List<Token> tokens, int from, int to) {
        Map<String, int[]> properties = new LinkedHashMap<>();
        int open = from;
        int close = Tokens.matching(tokens, open);
        if (close > 0) {
            to = Math.min(to, close);
        }
        int i = open + 1;
        while (i < to) {
            Token token = tokens.get(i);
            if (token.isPunct(",")) {
                i++;
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

    private static int[] objectPropertyRange(List<Token> tokens, int from, int to, String key) {
        if (!tokens.get(from).isPunct("{")) {
            return null;
        }
        for (Map.Entry<String, int[]> entry : objectProperties(tokens, from, to).entrySet()) {
            if (entry.getKey().equalsIgnoreCase(key)) {
                return entry.getValue();
            }
        }
        return null;
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
}
