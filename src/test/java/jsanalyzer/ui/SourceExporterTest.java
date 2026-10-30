package jsanalyzer.ui;

import jsanalyzer.store.JsFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/** Regression tests for exporting collected JavaScript sources. */
public final class SourceExporterTest {

    private static int passed;
    private static int failed;

    public static void main(String[] args) throws Exception {
        Set<String> used = new HashSet<>();
        check("path.basic", "example.test/static/app.js",
                SourceExporter.relativePath(file("https://example.test/static/app.js"), used));
        check("path.noExtension", "example.test/bundle.js",
                SourceExporter.relativePath(file("https://example.test/bundle?v=1"), used));
        check("path.root", "example.test/index.js",
                SourceExporter.relativePath(file("https://example.test/"), used));

        Set<String> traversal = new HashSet<>();
        String escaped = SourceExporter.relativePath(
                file("https://example.test/../../etc/passwd"), traversal);
        check("path.traversal", false, escaped.contains(".."));
        check("path.traversalValue", "example.test/etc/passwd.js", escaped);

        Set<String> collisions = new HashSet<>();
        check("path.collision1", "example.test/a.js",
                SourceExporter.relativePath(file("https://example.test/a.js"), collisions));
        check("path.collision2", "example.test/a_2.js",
                SourceExporter.relativePath(file("http://example.test/a.js"), collisions));
        check("path.collision3", "example.test/a_3.js",
                SourceExporter.relativePath(file("https://example.test/a.js?x=1"), collisions));

        check("sanitize.host", "sub.example-test.com",
                SourceExporter.sanitize("sub.example-test.com"));
        check("sanitize.weird", "a_b", SourceExporter.sanitize("a b"));

        Path temp = Files.createTempDirectory("js-analyzer-export-test");
        try {
            JsFile one = file("https://example.test/static/app.js");
            one.contentHash = jsanalyzer.store.AnalysisStore.contentHash("fetch('/api/v1/users');\n");
            one.size = "fetch('/api/v1/users');\n".length();
            JsFile two = file("http://example.test/static/app.js");
            two.contentHash = "stale-hash"; // content changed since analysis
            two.size = "const token = 'abc';\n".length();
            JsFile missing = file("https://example.test/missing.js");

            java.util.Map<String, String> bodies = java.util.Map.of(
                    "https://example.test/static/app.js", "fetch('/api/v1/users');\n",
                    "http://example.test/static/app.js", "const token = 'abc';\n");
            jsanalyzer.store.SourceProvider provider = url -> {
                String body = bodies.get(url);
                if (body == null) {
                    throw new java.io.IOException("HTTP 401 when refetching");
                }
                return body;
            };

            SourceExporter.Result result = SourceExporter.export(List.of(one, two, missing), temp,
                    provider);
            check("export.count", 2, result.exported);
            check("export.skipped", 1, result.skipped);
            check("export.changed", 1, result.changed);
            check("export.errors", 1, result.errors.size());
            check("export.errorReason", true, result.errors.get(0).contains("HTTP 401"));
            check("export.manifest", true, Files.isRegularFile(temp.resolve("_manifest.tsv")));
            check("export.report", true, Files.isRegularFile(temp.resolve("_report.txt")));

            List<String> written;
            try (Stream<Path> walk = Files.walk(temp)) {
                written = walk.filter(Files::isRegularFile)
                        .map(path -> temp.relativize(path).toString().replace('\\', '/'))
                        .filter(name -> name.endsWith(".js"))
                        .sorted()
                        .collect(Collectors.toList());
            }
            check("export.files", List.of("example.test/static/app.js", "example.test/static/app_2.js"),
                    written);
            check("export.content", "fetch('/api/v1/users');\n",
                    Files.readString(temp.resolve("example.test/static/app.js")));
            check("export.conflictContent", "const token = 'abc';\n",
                    Files.readString(temp.resolve("example.test/static/app_2.js")));

            List<String> manifestLines = Files.readAllLines(temp.resolve("_manifest.tsv"));
            check("export.manifestLines", 3, manifestLines.size());
            check("export.manifestHeader", true,
                    manifestLines.get(0).startsWith("saved_file\turl\tstatus"));
            check("export.manifestUrls", true,
                    manifestLines.get(1).contains("https://example.test/static/app.js")
                            && manifestLines.get(2).contains("http://example.test/static/app.js"));
            check("export.manifestUnchanged", true, manifestLines.get(1).endsWith("\tno"));
            check("export.manifestChanged", true, manifestLines.get(2).endsWith("\tyes"));
        } finally {
            try (Stream<Path> walk = Files.walk(temp)) {
                for (Path path : walk.sorted((a, b) -> b.getNameCount() - a.getNameCount())
                        .collect(Collectors.toList())) {
                    Files.deleteIfExists(path);
                }
            }
        }

        System.out.println("passed: " + passed + ", failed: " + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    private static JsFile file(String url) {
        return new JsFile(url, url, host(url), 200, "application/javascript", 0, "hash");
    }

    private static String host(String url) {
        try {
            String host = java.net.URI.create(url).getHost();
            return host == null ? "" : host;
        } catch (RuntimeException ignored) {
            return "";
        }
    }

    private static void check(String name, Object expected, Object actual) {
        if (java.util.Objects.equals(expected, actual)) {
            passed++;
        } else {
            failed++;
            System.out.println("FAIL " + name + " expected <" + expected + "> but was <" + actual + ">");
        }
    }
}
