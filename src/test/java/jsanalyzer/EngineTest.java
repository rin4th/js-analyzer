package jsanalyzer;

import jsanalyzer.engine.Analyzer;
import jsanalyzer.model.AjaxFinding;
import jsanalyzer.model.AnalysisResult;
import jsanalyzer.model.DomXssFinding;
import jsanalyzer.model.EndpointFinding;
import jsanalyzer.model.FunctionFinding;
import jsanalyzer.model.SensitiveFinding;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Plain-Java regression suite for the analysis engine. Mirrors the cases of the
 * js-extractor project so both implementations report the same kind of results.
 * Run with {@code ./build.sh test} (no JUnit needed).
 */
public final class EngineTest {

    private static int passed;
    private static int failed;
    private static final List<String> failures = new ArrayList<>();

    public static void main(String[] args) {
        domXssTests();
        endpointTests();
        sensitiveTests();
        ajaxTests();
        functionTests();
        combinedTests();
        syntaxStressTests();
        bindingSpaceTests();

        System.out.println();
        System.out.println("passed: " + passed + ", failed: " + failed);
        if (failed > 0) {
            System.out.println();
            for (String failure : failures) {
                System.out.println("FAIL " + failure);
            }
            System.exit(1);
        }
    }

    // ------------------------------------------------------------------
    // DOM XSS
    // ------------------------------------------------------------------

    private static void domXssTests() {
        String direct = "const output = document.querySelector('#output');\n"
                + "output.innerHTML = location.hash;";
        List<DomXssFinding> directFindings = Analyzer.analyze(direct).domXssFindings;
        check("dom.direct.count", directFindings.size(), 1);
        if (directFindings.size() == 1) {
            DomXssFinding finding = directFindings.get(0);
            check("dom.direct.sink", finding.sink(), "innerHTML");
            check("dom.direct.source", finding.source(), "location.hash");
            check("dom.direct.line", finding.line(), 2);
            check("dom.direct.severity", finding.severity(), "high");
            check("dom.direct.confidence", finding.confidence(), "high");
            check("dom.direct.path", finding.path(), List.of("location.hash", "innerHTML"));
            check("dom.direct.range", direct.substring(finding.start(), finding.end()),
                    "output.innerHTML = location.hash;");
        }

        String aliases = "const raw = location.search;\n"
                + "const alias = '<strong>' + raw + '</strong>';\n"
                + "const markup = `<section>${alias}</section>`;\n"
                + "panel.innerHTML = markup;";
        List<DomXssFinding> aliasFindings = Analyzer.analyze(aliases).domXssFindings;
        check("dom.alias.count", aliasFindings.size(), 1);
        if (aliasFindings.size() == 1) {
            check("dom.alias.source", aliasFindings.get(0).source(), "location.search");
            check("dom.alias.path", aliasFindings.get(0).path(),
                    List.of("location.search", "raw", "alias", "markup", "innerHTML"));
            check("dom.alias.confidence", aliasFindings.get(0).confidence(), "high");
        }

        String sinks = "node.insertAdjacentHTML('beforeend', location.search);\n"
                + "document.write(document.URL);\n"
                + "eval(window.location.hash);\n"
                + "$('#preview').html(event.data);";
        List<DomXssFinding> sinkFindings = Analyzer.analyze(sinks).domXssFindings;
        check("dom.sinks.list", sinkFindings.stream().map(DomXssFinding::sink).collect(Collectors.toList()),
                List.of("insertAdjacentHTML", "document.write", "eval", "jQuery.html"));
        check("dom.sinks.severity",
                sinkFindings.stream().allMatch(f -> f.severity().equals("high")), true);
        check("dom.sinks.sources",
                sinkFindings.stream().map(DomXssFinding::source).collect(Collectors.toList()),
                List.of("location.search", "document.URL", "window.location.hash", "event.data"));

        String functionCtor = "Function(location.hash);\nnew Function(location.search);";
        List<DomXssFinding> ctorFindings = Analyzer.analyze(functionCtor).domXssFindings;
        check("dom.ctor.sinks",
                ctorFindings.stream().map(DomXssFinding::sink).collect(Collectors.toList()),
                List.of("Function constructor", "Function constructor"));
        check("dom.ctor.sources",
                ctorFindings.stream().map(DomXssFinding::source).collect(Collectors.toList()),
                List.of("location.hash", "location.search"));

        String react = "React.createElement('div', {\n"
                + "  dangerouslySetInnerHTML: { __html: location.hash }\n"
                + "});\n"
                + "React.createElement('div', {\n"
                + "  dangerouslySetInnerHTML: { __html: '<strong>constant</strong>' }\n"
                + "});";
        List<DomXssFinding> reactFindings = Analyzer.analyze(react).domXssFindings;
        check("dom.react.count", reactFindings.size(), 1);
        if (reactFindings.size() == 1) {
            check("dom.react.sink", reactFindings.get(0).sink(), "React.dangerouslySetInnerHTML");
            check("dom.react.source", reactFindings.get(0).source(), "location.hash");
            check("dom.react.confidence", reactFindings.get(0).confidence(), "high");
        }

        String params = "function renderPreview(markup) {\n"
                + "  preview.innerHTML = markup;\n"
                + "}\n"
                + "renderPreview(location.hash);";
        List<DomXssFinding> paramFindings = Analyzer.analyze(params).domXssFindings;
        check("dom.params.count", paramFindings.size(), 1);
        if (paramFindings.size() == 1) {
            DomXssFinding finding = paramFindings.get(0);
            check("dom.params.sink", finding.sink(), "innerHTML");
            check("dom.params.source", finding.source(), "location.hash");
            check("dom.params.line", finding.line(), 2);
            check("dom.params.confidence", finding.confidence(), "high");
            check("dom.params.path", finding.path(), List.of("location.hash", "markup", "innerHTML"));
        }

        String sanitized = "safeNode.textContent = location.hash;\n"
                + "constantNode.innerHTML = '<strong>Known-safe constant</strong>';\n"
                + "const clean = DOMPurify.sanitize(location.search);\n"
                + "sanitizedNode.innerHTML = clean;\n"
                + "const policy = trustedTypes.createPolicy('app', { createHTML: value => DOMPurify.sanitize(value) });\n"
                + "trustedNode.innerHTML = policy.createHTML(location.hash);";
        check("dom.sanitized.count", Analyzer.analyze(sanitized).domXssFindings.size(), 0);

        String identity = "const unsafePolicy = trustedTypes.createPolicy('unsafe', {\n"
                + "  createHTML: value => value\n"
                + "});\n"
                + "target.innerHTML = unsafePolicy.createHTML(location.hash);";
        List<DomXssFinding> identityFindings = Analyzer.analyze(identity).domXssFindings;
        check("dom.identity.count", identityFindings.size(), 1);
        if (identityFindings.size() == 1) {
            check("dom.identity.sink", identityFindings.get(0).sink(), "innerHTML");
            check("dom.identity.source", identityFindings.get(0).source(), "location.hash");
            check("dom.identity.severity", identityFindings.get(0).severity(), "high");
        }

        String custom = "function sanitizeHTML(value) { return value; }\n"
                + "target.innerHTML = sanitizeHTML(location.hash);";
        check("dom.customSanitizer.count", Analyzer.analyze(custom).domXssFindings.size(), 1);

        String jquery = "$('#one').append(location.hash);\n"
                + "$('#two').prepend(location.search);\n"
                + "$('#three').before(document.URL);\n"
                + "$('#four').after(event.data);\n"
                + "$('#five').replaceWith(window.location.hash);";
        check("dom.jquery.list",
                Analyzer.analyze(jquery).domXssFindings.stream().map(DomXssFinding::sink)
                        .collect(Collectors.toList()),
                List.of("jQuery.append", "jQuery.prepend", "jQuery.before", "jQuery.after",
                        "jQuery.replaceWith"));

        String attributes = "frame.setAttribute('srcdoc', location.hash);\n"
                + "button.setAttribute('onclick', location.search);\n"
                + "button.setAttribute(dynamicName, location.hash);";
        List<DomXssFinding> attributeFindings = Analyzer.analyze(attributes).domXssFindings;
        check("dom.setAttribute.list",
                attributeFindings.stream().map(DomXssFinding::sink).collect(Collectors.toList()),
                List.of("setAttribute(srcdoc)", "setAttribute(onclick)"));
        check("dom.setAttribute.confidence",
                attributeFindings.stream().allMatch(f -> f.confidence().equals("high")), true);

        String searchParams = "const params = new URLSearchParams(location.search);\n"
                + "const query = params.get('q').slice(1).trim();\n"
                + "result.innerHTML = query;";
        List<DomXssFinding> searchFindings = Analyzer.analyze(searchParams).domXssFindings;
        check("dom.urlSearchParams.count", searchFindings.size(), 1);
        if (searchFindings.size() == 1) {
            DomXssFinding finding = searchFindings.get(0);
            check("dom.urlSearchParams.sink", finding.sink(), "innerHTML");
            check("dom.urlSearchParams.source", finding.source(), "location.search");
            check("dom.urlSearchParams.confidence", finding.confidence(), "high");
            check("dom.urlSearchParams.pathContains",
                    finding.path().containsAll(List.of("URLSearchParams()", "params", "query", "innerHTML")),
                    true);
        }

        String unresolved = "target.outerHTML = serverResponse;";
        List<DomXssFinding> unresolvedFindings = Analyzer.analyze(unresolved).domXssFindings;
        check("dom.unresolved.count", unresolvedFindings.size(), 1);
        if (unresolvedFindings.size() == 1) {
            DomXssFinding finding = unresolvedFindings.get(0);
            check("dom.unresolved.sink", finding.sink(), "outerHTML");
            check("dom.unresolved.source", finding.source(), "Unresolved dynamic value");
            check("dom.unresolved.severity", finding.severity(), "medium");
            check("dom.unresolved.confidence", finding.confidence(), "low");
            check("dom.unresolved.path", finding.path(), List.of("outerHTML"));
        }

        String malformed = "const broken = ;\nconst payload = location.hash;\ntarget.innerHTML = payload;";
        AnalysisResult malformedResult = Analyzer.analyze(malformed);
        check("dom.malformed.parseError", malformedResult.parseError != null, true);
        check("dom.malformed.count", malformedResult.domXssFindings.size(), 1);
        if (malformedResult.domXssFindings.size() == 1) {
            DomXssFinding finding = malformedResult.domXssFindings.get(0);
            check("dom.malformed.sink", finding.sink(), "innerHTML");
            check("dom.malformed.source", finding.source(), "location.hash");
            check("dom.malformed.line", finding.line(), 3);
            check("dom.malformed.range", malformed.substring(finding.start(), finding.end()),
                    "target.innerHTML = payload;");
        }
    }

    // ------------------------------------------------------------------
    // Endpoints, secrets
    // ------------------------------------------------------------------

    private static void endpointTests() {
        String source = "\n"
                + "      const absolute = 'https://target.test/api/users';\n"
                + "      const api = '/api/v1/files';\n"
                + "      const handler = 'handlers/upload.ashx?mode=create';\n"
                + "      const apiAgain = '/api/v1/files';\n"
                + "    ";
        List<EndpointFinding> endpoints = Analyzer.analyze(source).endpoints;
        check("endpoints.list", endpoints,
                List.of(new EndpointFinding("https://target.test/api/users", "absolute", 2),
                        new EndpointFinding("/api/v1/files", "api", 3),
                        new EndpointFinding("handlers/upload.ashx?mode=create", "server-script", 4)));

        // The method is read where the code passes one; bare strings have none.
        String calls = "fetch('/api/v2/orders', { method: 'POST' });\n"
                + "fetch('/api/v2/orders', { method: 'GET' });\n"
                + "const bare = '/api/v2/bare';\n"
                + "fetch('/api/v2/only-call');\n";
        List<EndpointFinding> withMethods = Analyzer.analyze(calls).endpoints;
        checkTrue("endpoints.method.multiple", withMethods.stream().anyMatch(endpoint ->
                        endpoint.value().equals("/api/v2/orders")
                                && endpoint.method().equals("GET, POST")),
                withMethods.toString());
        checkTrue("endpoints.method.unknown", withMethods.stream().anyMatch(endpoint ->
                        endpoint.value().equals("/api/v2/bare") && endpoint.method().isEmpty()),
                withMethods.toString());
        checkTrue("endpoints.method.ajaxOnly", withMethods.stream().anyMatch(endpoint ->
                        endpoint.value().equals("/api/v2/only-call")
                                && endpoint.method().equals("GET")),
                withMethods.toString());
    }

    private static void sensitiveTests() {
        String source = "\n"
                + "      const api_key = 'demo-key';\n"
                + "      const config = { password: 'hunter2' };\n"
                + "      console.log('Bearer ey.example');\n"
                + "    ";
        List<SensitiveFinding> findings = Analyzer.analyze(source).sensitiveFindings;
        checkTrue("sensitive.api_key", findings.stream().anyMatch(f -> f.keyword().equals("api_key")
                && f.value().equals("'demo-key'") && f.line() == 2), findings.toString());
        checkTrue("sensitive.password", findings.stream().anyMatch(f -> f.keyword().equals("password")
                && f.value().equals("'hunter2'") && f.line() == 3), findings.toString());
        checkTrue("sensitive.bearer", findings.stream().anyMatch(f -> f.keyword().equals("bearer")
                && f.value().equals("Bearer ey.example") && f.line() == 4), findings.toString());
    }

    // ------------------------------------------------------------------
    // Ajax
    // ------------------------------------------------------------------

    private static void ajaxTests() {
        String fetchSource = "\n"
                + "      const base = '/api/v1';\n"
                + "      const payload = { oldName: 'a', newName: 'b', meta: { admin: true } };\n"
                + "      fetch(base + '/rename?id=12', {\n"
                + "        method: 'POST',\n"
                + "        body: JSON.stringify(payload)\n"
                + "      });\n"
                + "    ";
        List<AjaxFinding> fetchCalls = Analyzer.analyze(fetchSource).ajaxCalls;
        check("ajax.fetch", fetchCalls, List.of(new AjaxFinding("fetch", "/api/v1/rename?id=12", "POST",
                List.of("oldName", "newName", "meta", "admin", "id"), 4)));

        String jquerySource = "\n"
                + "      $.ajax({\n"
                + "        url: '/admin/create.php',\n"
                + "        type: 'PUT',\n"
                + "        data: { username: user, role: 'admin' }\n"
                + "      });\n"
                + "    ";
        check("ajax.jquery", Analyzer.analyze(jquerySource).ajaxCalls,
                List.of(new AjaxFinding("jquery.ajax", "/admin/create.php", "PUT",
                        List.of("username", "role"), 2)));

        String xhrSource = "\n"
                + "      const form = new FormData();\n"
                + "      form.append('file', selectedFile);\n"
                + "      form.append('destination', '/tmp');\n"
                + "      const xhr = new XMLHttpRequest();\n"
                + "      xhr.open('POST', '/api/v2/upload?overwrite=true');\n"
                + "      xhr.send(form);\n"
                + "    ";
        check("ajax.xhr", Analyzer.analyze(xhrSource).ajaxCalls,
                List.of(new AjaxFinding("XMLHttpRequest", "/api/v2/upload?overwrite=true", "POST",
                        List.of("overwrite", "file", "destination"), 6)));
    }

    // ------------------------------------------------------------------
    // Functions
    // ------------------------------------------------------------------

    private static void functionTests() {
        String source = "\n"
                + "      function uploadAvatar(file) { return file; }\n"
                + "      const deleteUser = async (id) => id;\n"
                + "      const actions = { renameAsset(from, to) { return [from, to]; } };\n"
                + "      class Controller { executeCommand(command) { return command; } }\n"
                + "    ";
        List<FunctionFinding> functions = Analyzer.analyze(source).interestingFunctions;
        check("functions.names",
                functions.stream().map(f -> f.name() + ":" + f.matchedAction()).collect(Collectors.toList()),
                List.of("uploadAvatar:upload", "deleteUser:delete", "renameAsset:rename",
                        "executeCommand:execute"));
        check("functions.signatures", functions.stream().allMatch(f -> f.signature().contains("(")), true);
        check("functions.ranges",
                functions.stream().map(f -> source.substring(f.start(), f.end())).collect(Collectors.toList()),
                List.of("function uploadAvatar(file) { return file; }",
                        "const deleteUser = async (id) => id;",
                        "renameAsset(from, to) { return [from, to]; }",
                        "executeCommand(command) { return command; }"));

        String multiline = "export async function uploadReport(file) {\n"
                + "  const closingBrace = \"}\";\n"
                + "  return { file, closingBrace };\n"
                + "}\n"
                + "\n"
                + "window.deleteAccount = function (id) {\n"
                + "  return request(id);\n"
                + "};\n"
                + "\n"
                + "const actions = {\n"
                + "  renameAsset: (from, to) => {\n"
                + "    return { from, to };\n"
                + "  }\n"
                + "};";
        List<FunctionFinding> multilineFunctions = Analyzer.analyze(multiline).interestingFunctions;
        java.util.Map<String, String> snippets = new java.util.LinkedHashMap<>();
        for (FunctionFinding finding : multilineFunctions) {
            snippets.put(finding.name(), multiline.substring(finding.start(), finding.end()));
        }
        check("functions.uploadReport", snippets.get("uploadReport"),
                "export async function uploadReport(file) {\n"
                        + "  const closingBrace = \"}\";\n"
                        + "  return { file, closingBrace };\n"
                        + "}");
        check("functions.deleteAccount", snippets.get("window.deleteAccount"),
                "window.deleteAccount = function (id) {\n"
                        + "  return request(id);\n"
                        + "};");
        check("functions.renameAsset", snippets.get("renameAsset"),
                "renameAsset: (from, to) => {\n"
                        + "    return { from, to };\n"
                        + "  }");

        String malformed = "const broken = ;\n"
                + "function uploadFallback(file) {\n"
                + "  const closingBrace = \"}\";\n"
                + "  return file;\n"
                + "}\n"
                + "const deleteFallback = (id) => {\n"
                + "  // A brace in a comment must not end the function: }\n"
                + "  return id;\n"
                + "};\n"
                + "const renameFallback = value => value.trim();\n"
                + "function createDangling(value)";
        AnalysisResult analysis = Analyzer.analyze(malformed);
        java.util.Map<String, String> fallbackSnippets = new java.util.LinkedHashMap<>();
        for (FunctionFinding finding : analysis.interestingFunctions) {
            fallbackSnippets.put(finding.name(), malformed.substring(finding.start(), finding.end()));
        }
        check("functions.malformed.parseError", analysis.parseError != null, true);
        check("functions.fallback.upload", fallbackSnippets.get("uploadFallback"),
                "function uploadFallback(file) {\n"
                        + "  const closingBrace = \"}\";\n"
                        + "  return file;\n"
                        + "}");
        check("functions.fallback.delete", fallbackSnippets.get("deleteFallback"),
                "const deleteFallback = (id) => {\n"
                        + "  // A brace in a comment must not end the function: }\n"
                        + "  return id;\n"
                        + "};");
        check("functions.fallback.rename", fallbackSnippets.get("renameFallback"),
                "const renameFallback = value => value.trim();");
        check("functions.fallback.dangling", fallbackSnippets.get("createDangling"),
                "function createDangling(value)");
    }

    // ------------------------------------------------------------------
    // Combined
    // ------------------------------------------------------------------

    private static void combinedTests() {
        AnalysisResult valid = Analyzer.analyze("fetch('/api/files', { body: { token: value } })");
        check("combined.valid.parseError", valid.parseError, null);
        check("combined.valid.endpoint", valid.endpoints.get(0),
                new EndpointFinding("/api/files", "api", 1, "GET"));
        checkTrue("combined.valid.ajax", valid.ajaxCalls.stream().anyMatch(call ->
                call.type().equals("fetch") && call.url().equals("/api/files")), valid.ajaxCalls.toString());

        String malformedSource = "const api_key = ; fetch('/fallback.php')";
        AnalysisResult malformed = Analyzer.analyze(malformedSource);
        check("combined.malformed.parseError", malformed.parseError != null, true);
        checkTrue("combined.malformed.endpoint", malformed.endpoints.stream().anyMatch(endpoint ->
                endpoint.value().equals("/fallback.php") && endpoint.type().equals("server-script")
                        && endpoint.line() == 1), malformed.endpoints.toString());
        checkTrue("combined.malformed.ajax", malformed.ajaxCalls.stream().anyMatch(call ->
                call.type().equals("fetch") && call.url().equals("/fallback.php")
                        && call.method().equals("GET")), malformed.ajaxCalls.toString());

        String styles = "\n"
                + "      const broken = ;\n"
                + "      fetch('/fallback-fetch', { method: 'PATCH', body: { itemId: 7 } });\n"
                + "      $.ajax({ url: '/fallback-ajax.php', type: 'POST', data: { role: 'admin' } });\n"
                + "      const form = new FormData();\n"
                + "      form.append('file', selectedFile);\n"
                + "      form.set('overwrite', true);\n"
                + "      const request = new XMLHttpRequest();\n"
                + "      request.open('PUT', '/fallback-xhr.ashx?mode=replace');\n"
                + "      request.send(form);\n"
                + "      const deleteFallback = id => id;\n"
                + "    ";
        AnalysisResult fallback = Analyzer.analyze(styles);
        check("combined.styles.parseError", fallback.parseError != null, true);
        check("combined.styles.ajax",
                fallback.ajaxCalls.stream()
                        .map(call -> call.type() + "|" + call.method() + "|" + call.url() + "|"
                                + call.parameters() + "|" + call.line())
                        .collect(Collectors.toList()),
                List.of("fetch|PATCH|/fallback-fetch|[itemId]|3",
                        "jquery.ajax|POST|/fallback-ajax.php|[role]|4",
                        "XMLHttpRequest|PUT|/fallback-xhr.ashx?mode=replace|[mode, file, overwrite]|9"));
        checkTrue("combined.styles.function", fallback.interestingFunctions.stream().anyMatch(finding ->
                finding.name().equals("deleteFallback") && finding.matchedAction().equals("delete")
                        && finding.signature().equals("deleteFallback(id)")),
                fallback.interestingFunctions.toString());
    }

    // ------------------------------------------------------------------
    // Modern syntax robustness
    // ------------------------------------------------------------------

    private static void syntaxStressTests() {
        String source = "class Repo {\n"
                + "  #token = 'abc';\n"
                + "  static #cache = new Map();\n"
                + "  static { this.#cache.set('x', 1); }\n"
                + "  async list(url) {\n"
                + "    const endpoint = url ?? '/api/v9/items';\n"
                + "    return await fetch(endpoint).then(r => r?.json?.());\n"
                + "  }\n"
                + "  #secret() { return this.#token; }\n"
                + "}\n"
                + "const href = 'https://cdn.example.test/lib.js';\n"
                + "const nested = `/api/v1/${`x${href}`}`;\n"
                + "label.innerHTML = location.search ?? '';\n"
                + "const re = /https?:\\/\\/[^'\"]+/g;";
        AnalysisResult result = Analyzer.analyze(source);
        check("stress.parseError", null, result.parseError);
        checkTrue("stress.endpoint.api", result.endpoints.stream().anyMatch(e ->
                e.value().equals("/api/v9/items")), result.endpoints.toString());
        checkTrue("stress.endpoint.absolute", result.endpoints.stream().anyMatch(e ->
                e.value().equals("https://cdn.example.test/lib.js")), result.endpoints.toString());
        checkTrue("stress.dom", result.domXssFindings.stream().anyMatch(f ->
                f.sink().equals("innerHTML") && f.source().equals("location.search")),
                result.domXssFindings.toString());
        checkTrue("stress.fetch", result.ajaxCalls.stream().anyMatch(c ->
                c.url().equals("/api/v9/items")), result.ajaxCalls.toString());
        checkTrue("stress.privateFieldNotSensitive", result.sensitiveFindings.stream().noneMatch(f ->
                f.value().contains("#token")), result.sensitiveFindings.toString());
    }

    // ------------------------------------------------------------------
    // Bindings across re-lexed token lists
    // ------------------------------------------------------------------

    /**
     * A template expression is re-lexed on its own, so its token indices differ
     * from the file-wide list. Binding ranges must never be applied to that
     * smaller list; the bound text is what carries over.
     */
    private static void bindingSpaceTests() {
        String fetchTemplate = "const base = '/api';fetch(`${base}/users`);";
        check("bindings.template.fetch", Analyzer.analyze(fetchTemplate).ajaxCalls,
                List.of(new AjaxFinding("fetch", "${/api}/users", "GET", List.of(), 1)));

        String twoBindings = "const apiBase = '/api/v1';const p = '/products';"
                + "fetch(`${apiBase}${p}?id=1`);";
        check("bindings.template.twoIdentifiers", Analyzer.analyze(twoBindings).ajaxCalls,
                List.of(new AjaxFinding("fetch", "${/api/v1}${/products}?id=1", "GET",
                        List.of("id"), 1)));

        String jqueryTemplate = "let u = '/x';$.ajax({url: `${u}/y`});";
        check("bindings.template.jquery", Analyzer.analyze(jqueryTemplate).ajaxCalls,
                List.of(new AjaxFinding("jquery.ajax", "${/x}/y", "GET", List.of(), 1)));

        String nested = "const href = 'https://cdn.example.test/a.js';"
                + "fetch(`/api/v1/${`x${href}`}`);";
        checkTrue("bindings.template.nested", !Analyzer.analyze(nested).ajaxCalls.isEmpty(),
                Analyzer.analyze(nested).ajaxCalls.toString());

        // Deep chains and self-references must terminate instead of recursing.
        String chain = "const a = b;const b = c;const c = '/api/deep';fetch(`${a}`);";
        check("bindings.template.chain", Analyzer.analyze(chain).ajaxCalls,
                List.of(new AjaxFinding("fetch", "${/api/deep}", "GET", List.of(), 1)));

        String selfReference = "const loop = loop;fetch(`${loop}/x`);";
        checkTrue("bindings.template.selfReference",
                !Analyzer.analyze(selfReference).ajaxCalls.isEmpty(),
                Analyzer.analyze(selfReference).ajaxCalls.toString());
    }

    // ------------------------------------------------------------------
    // Assertions
    // ------------------------------------------------------------------

    private static void check(String name, Object expected, Object actual) {
        if (Objects.equals(expected, actual)) {
            passed++;
        } else {
            failed++;
            failures.add(name + " expected <" + expected + "> but was <" + actual + ">");
        }
    }

    private static void checkTrue(String name, boolean condition, String detail) {
        if (condition) {
            passed++;
        } else {
            failed++;
            failures.add(name + " expected true, detail: " + detail);
        }
    }
}
