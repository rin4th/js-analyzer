package jsanalyzer.ui;

import jsanalyzer.model.AjaxFinding;
import jsanalyzer.model.AnalysisResult;
import jsanalyzer.model.DomXssFinding;
import jsanalyzer.model.EndpointFinding;
import jsanalyzer.model.FunctionFinding;
import jsanalyzer.model.SensitiveFinding;
import jsanalyzer.store.JsFile;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/** Plain-text export of the collected findings. */
public final class ReportBuilder {

    private static final DateTimeFormatter TIME =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z");

    private ReportBuilder() {
    }

    public static String build(List<JsFile> files) {
        StringBuilder builder = new StringBuilder();
        builder.append("JS Analyzer report\n");
        builder.append("Generated: ").append(TIME.format(ZonedDateTime.now())).append("\n");
        builder.append("Files: ").append(files.size()).append("\n");
        builder.append("Note: static-analysis leads; validate every finding manually.\n\n");
        for (JsFile file : files) {
            builder.append(build(file)).append('\n');
        }
        return builder.toString();
    }

    public static String build(JsFile file) {
        StringBuilder builder = new StringBuilder();
        AnalysisResult result = file.result;
        builder.append("=== ").append(file.url).append('\n');
        builder.append("Status: ").append(file.status);
        if (result == null) {
            if (file.error != null) {
                builder.append(" (").append(file.error).append(')');
            }
            builder.append("\n");
            return builder.toString();
        }
        builder.append(" | HTTP ").append(file.statusCode)
                .append(" | ").append(FilesTableModel.formatSize(file.size))
                .append(" | ").append(result.lineCount).append(" lines")
                .append(" | ").append(result.durationMs).append(" ms")
                .append(" | seen ").append(file.hits).append("x\n");
        if (result.parseError != null) {
            builder.append("Parser note: ").append(result.parseError).append(" (heuristic results)\n");
        }
        builder.append('\n');

        builder.append("Endpoints (").append(result.endpoints.size()).append(")\n");
        for (EndpointFinding endpoint : result.endpoints) {
            builder.append("  [").append(endpoint.type()).append("] ").append(endpoint.value())
                    .append("  ").append(endpoint.method().isEmpty() ? "-" : endpoint.method())
                    .append("  (L").append(endpoint.line()).append(")\n");
        }
        builder.append('\n');

        builder.append("Secrets (").append(result.sensitiveFindings.size()).append(")\n");
        for (SensitiveFinding finding : result.sensitiveFindings) {
            builder.append("  ").append(finding.keyword()).append(": ").append(finding.value())
                    .append("  (L").append(finding.line()).append(", ").append(finding.context()).append(")\n");
        }
        builder.append('\n');

        builder.append("Ajax / Fetch (").append(result.ajaxCalls.size()).append(")\n");
        for (AjaxFinding call : result.ajaxCalls) {
            builder.append("  ").append(call.method()).append(' ').append(call.url())
                    .append("  [").append(call.type()).append(", L").append(call.line()).append("]");
            if (!call.parameters().isEmpty()) {
                builder.append("  params: ").append(String.join(", ", call.parameters()));
            }
            builder.append('\n');
        }
        builder.append('\n');

        builder.append("Potential DOM XSS (").append(result.domXssFindings.size()).append(")\n");
        for (DomXssFinding finding : result.domXssFindings) {
            builder.append("  ").append(finding.sink()).append(" <- ").append(finding.source())
                    .append("  [").append(finding.severity()).append('/').append(finding.confidence())
                    .append(", L").append(finding.line()).append("]\n");
            if (finding.path() != null && finding.path().size() > 1) {
                builder.append("    flow: ").append(String.join(" -> ", finding.path())).append('\n');
            }
        }
        builder.append('\n');

        builder.append("Interesting functions (").append(result.interestingFunctions.size()).append(")\n");
        for (FunctionFinding function : result.interestingFunctions) {
            builder.append("  ").append(function.signature())
                    .append("  [").append(function.matchedAction()).append(", L")
                    .append(function.line()).append("]\n");
        }
        return builder.toString();
    }
}
