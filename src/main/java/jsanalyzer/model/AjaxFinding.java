package jsanalyzer.model;

import java.util.List;

/** fetch / jQuery Ajax / XMLHttpRequest call recovered from JavaScript. */
public record AjaxFinding(String type, String url, String method, List<String> parameters, int line) {

    public AjaxFinding {
        parameters = List.copyOf(parameters);
    }
}
