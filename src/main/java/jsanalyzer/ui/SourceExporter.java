package jsanalyzer.ui;

import jsanalyzer.store.AnalysisStore;
import jsanalyzer.store.JsFile;
import jsanalyzer.store.SourceProvider;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Writes the collected JavaScript files to a directory, preserving the host and
 * path structure (for example {@code example.test/static/app.js}), plus a TSV
 * manifest and a plain-text findings report.
 *
 * <p>Bodies are no longer held in memory, so each file is fetched again through
 * the {@link SourceProvider} and written straight to disk; only one body is in
 * memory at a time. A file whose content changed since it was analyzed is
 * marked in the manifest instead of being reported as identical.</p>
 */
public final class SourceExporter {

    /** Reports export progress so the UI can show "Exporting 3/36…". */
    public interface Progress {
        void onFile(int done, int total, String url);
    }

    public static final class Result {
        public final int exported;
        public final int skipped;
        public final int changed;
        public final Path directory;
        public final Path manifest;
        public final List<String> errors;

        Result(int exported, int skipped, int changed, Path directory, Path manifest,
               List<String> errors) {
            this.exported = exported;
            this.skipped = skipped;
            this.changed = changed;
            this.directory = directory;
            this.manifest = manifest;
            this.errors = List.copyOf(errors);
        }
    }

    private SourceExporter() {
    }

    public static Result export(List<JsFile> files, Path directory, SourceProvider provider) {
        return export(files, directory, provider, (done, total, url) -> { });
    }

    public static Result export(List<JsFile> files, Path directory, SourceProvider provider,
                                Progress progress) {
        List<String> errors = new ArrayList<>();
        Path root = directory.toAbsolutePath().normalize();
        try {
            Files.createDirectories(root);
        } catch (IOException exception) {
            errors.add("Cannot create " + root + ": " + exception.getMessage());
            return new Result(0, files.size(), 0, root, null, errors);
        }
        if (provider == null) {
            errors.add("No source provider: exporting needs Burp's HTTP stack");
            return new Result(0, files.size(), 0, root, null, errors);
        }

        StringBuilder manifest = new StringBuilder(
                "saved_file\turl\tstatus\tstatus_code\tcontent_type\tbytes\tendpoints\tsecrets\tajax"
                        + "\tdom_xss\tfunctions\tfirst_seen\tlast_seen\thits\tcontent_changed\n");
        Set<String> used = new HashSet<>();
        int exported = 0;
        int skipped = 0;
        int changed = 0;
        int done = 0;

        for (JsFile file : files) {
            progress.onFile(done, files.size(), file.url);
            done++;
            String body;
            try {
                body = provider.fetch(file.url);
            } catch (IOException | RuntimeException exception) {
                skipped++;
                errors.add("Cannot fetch " + file.url + ": " + exception.getMessage());
                continue;
            }
            if (body == null || body.isEmpty()) {
                skipped++;
                errors.add("Empty body for " + file.url);
                continue;
            }
            boolean contentChanged = file.contentHash != null
                    && !file.contentHash.equals(AnalysisStore.contentHash(body));
            if (contentChanged) {
                changed++;
            }
            String relative = relativePath(file, used);
            Path target = root.resolve(relative).normalize();
            if (!target.startsWith(root)) {
                skipped++;
                errors.add("Refused unsafe path for " + file.url);
                continue;
            }
            try {
                Path parent = target.getParent();
                if (parent != null) {
                    Files.createDirectories(parent);
                }
                Files.writeString(target, body, StandardCharsets.UTF_8);
                exported++;
                manifest.append(relative.replace('\\', '/')).append('\t')
                        .append(clean(file.url)).append('\t')
                        .append(file.status).append('\t')
                        .append(file.statusCode).append('\t')
                        .append(clean(file.contentType)).append('\t')
                        .append(file.size).append('\t')
                        .append(file.endpointCount()).append('\t')
                        .append(file.secretCount()).append('\t')
                        .append(file.ajaxCount()).append('\t')
                        .append(file.domXssCount()).append('\t')
                        .append(file.functionCount()).append('\t')
                        .append(Instant.ofEpochMilli(file.firstSeen)).append('\t')
                        .append(Instant.ofEpochMilli(file.lastSeen)).append('\t')
                        .append(file.hits).append('\t')
                        .append(contentChanged ? "yes" : "no").append('\n');
            } catch (IOException exception) {
                skipped++;
                errors.add("Cannot write " + relative + ": " + exception.getMessage());
            }
        }
        progress.onFile(files.size(), files.size(), "");

        Path manifestPath = root.resolve("_manifest.tsv");
        try {
            Files.writeString(manifestPath, manifest.toString(), StandardCharsets.UTF_8);
            Files.writeString(root.resolve("_report.txt"), ReportBuilder.build(files),
                    StandardCharsets.UTF_8);
        } catch (IOException exception) {
            errors.add("Cannot write manifest: " + exception.getMessage());
        }
        return new Result(exported, skipped, changed, root, manifestPath, errors);
    }

    /** Builds a safe relative path such as {@code host/dir/file.js}. */
    static String relativePath(JsFile file, Set<String> used) {
        String host = sanitize(file.host);
        if (host.isEmpty()) {
            host = "unknown-host";
        }
        String path = "/";
        try {
            URI uri = URI.create(file.url);
            if (uri.getPath() != null && !uri.getPath().isEmpty()) {
                path = uri.getPath();
            }
        } catch (RuntimeException ignored) {
            // Fall back to the root path for malformed URLs.
        }

        List<String> segments = new ArrayList<>();
        for (String raw : path.split("/")) {
            String segment = sanitize(raw);
            if (!segment.isEmpty() && !segment.equals(".") && !segment.equals("..")) {
                segments.add(segment);
            }
        }
        if (segments.isEmpty()) {
            segments.add("index.js");
        } else {
            int last = segments.size() - 1;
            if (!hasJsExtension(segments.get(last))) {
                segments.set(last, segments.get(last) + ".js");
            }
        }

        String relative = host + "/" + String.join("/", segments);
        String key = relative.toLowerCase(Locale.ROOT);
        if (!used.add(key)) {
            String base = relative;
            int counter = 2;
            do {
                relative = withSuffix(base, "_" + counter++);
                key = relative.toLowerCase(Locale.ROOT);
            } while (!used.add(key));
        }
        return relative;
    }

    private static String withSuffix(String path, String suffix) {
        int slash = path.lastIndexOf('/');
        int dot = path.lastIndexOf('.');
        if (dot > slash) {
            return path.substring(0, dot) + suffix + path.substring(dot);
        }
        return path + suffix;
    }

    private static boolean hasJsExtension(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        return lower.endsWith(".js") || lower.endsWith(".mjs") || lower.endsWith(".cjs")
                || lower.endsWith(".jsx") || lower.endsWith(".es6");
    }

    /** Keeps letters, digits, dot, dash and underscore; limits segment length. */
    static String sanitize(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < value.length() && builder.length() < 120; i++) {
            char c = value.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '.' || c == '-' || c == '_') {
                builder.append(c);
            } else {
                builder.append('_');
            }
        }
        String result = builder.toString().replaceAll("_+", "_");
        while (result.startsWith(".")) {
            result = result.substring(1);
        }
        return result;
    }

    private static String clean(String value) {
        return value == null ? "" : value.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }
}
