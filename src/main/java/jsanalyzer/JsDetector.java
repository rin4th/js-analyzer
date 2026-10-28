package jsanalyzer;

import java.util.Locale;

/**
 * Decides whether a response is JavaScript worth analyzing. Extension and
 * content-type based, with a guard against HTML error pages that servers
 * mistakenly serve for script requests.
 */
public final class JsDetector {

    /** Files larger than this are skipped to keep the proxy responsive. */
    public static final int MAX_BODY_BYTES = 8 * 1024 * 1024;

    private JsDetector() {
    }

    public static boolean looksLikeJavascript(String path, String contentType, String body) {
        if (body == null || body.isBlank()) {
            return false;
        }
        String lowerBody = body.stripLeading().toLowerCase(Locale.ROOT);
        if (lowerBody.startsWith("\uFEFF")) {
            lowerBody = lowerBody.substring(1).stripLeading();
        }
        if (lowerBody.startsWith("<!doctype html") || lowerBody.startsWith("<html")
                || lowerBody.startsWith("<?xml")) {
            return false;
        }
        String type = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        boolean scriptType = type.contains("javascript") || type.contains("ecmascript")
                || type.contains("jscript");
        boolean jsExtension = isJavascriptPath(path);
        if (!scriptType && !jsExtension) {
            return false;
        }
        // Source maps and JSON payloads often share the .js path but are data only.
        if (type.contains("json") || path != null && path.toLowerCase(Locale.ROOT).endsWith(".map")) {
            return false;
        }
        return true;
    }

    public static boolean isJavascriptPath(String path) {
        if (path == null) {
            return false;
        }
        String lower = path.toLowerCase(Locale.ROOT);
        return lower.endsWith(".js") || lower.endsWith(".mjs") || lower.endsWith(".cjs")
                || lower.endsWith(".jsx") || lower.endsWith(".es6");
    }
}
