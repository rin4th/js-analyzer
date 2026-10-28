package jsanalyzer.model;

import java.util.List;

/** Result of analyzing one JavaScript file. */
public final class AnalysisResult {

    public final List<EndpointFinding> endpoints;
    public final List<SensitiveFinding> sensitiveFindings;
    public final List<AjaxFinding> ajaxCalls;
    public final List<DomXssFinding> domXssFindings;
    public final List<FunctionFinding> interestingFunctions;
    public final String parseError;
    public final int lineCount;
    public final int byteLength;
    public final long durationMs;

    public AnalysisResult(List<EndpointFinding> endpoints,
                          List<SensitiveFinding> sensitiveFindings,
                          List<AjaxFinding> ajaxCalls,
                          List<DomXssFinding> domXssFindings,
                          List<FunctionFinding> interestingFunctions,
                          String parseError,
                          int lineCount,
                          int byteLength,
                          long durationMs) {
        this.endpoints = List.copyOf(endpoints);
        this.sensitiveFindings = List.copyOf(sensitiveFindings);
        this.ajaxCalls = List.copyOf(ajaxCalls);
        this.domXssFindings = List.copyOf(domXssFindings);
        this.interestingFunctions = List.copyOf(interestingFunctions);
        this.parseError = parseError;
        this.lineCount = lineCount;
        this.byteLength = byteLength;
        this.durationMs = durationMs;
    }

    public int totalFindings() {
        return endpoints.size() + sensitiveFindings.size() + ajaxCalls.size()
                + domXssFindings.size() + interestingFunctions.size();
    }
}
