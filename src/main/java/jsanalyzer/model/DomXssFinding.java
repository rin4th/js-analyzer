package jsanalyzer.model;

import java.util.List;

/** Potential DOM XSS dataflow lead. */
public record DomXssFinding(String sink, String source, int line, String severity, String confidence,
                            String evidence, List<String> path, int start, int end) {

    public DomXssFinding {
        path = List.copyOf(path);
    }
}
