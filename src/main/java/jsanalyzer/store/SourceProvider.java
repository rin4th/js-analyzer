package jsanalyzer.store;

import java.io.IOException;

/**
 * Supplies the JavaScript text for a collected URL on demand.
 *
 * <p>Bodies are not retained in memory after analysis, so exporting sources or
 * re-running the analysis has to fetch the file again. Production uses Burp's
 * proxy history first (the exact response that was analyzed, cookies already
 * applied) and Burp's HTTP stack as a fallback; tests inject a stub.</p>
 */
public interface SourceProvider {

    /** Returns the JavaScript body for {@code url}; throws when it cannot be obtained. */
    String fetch(String url) throws IOException;
}
