package jsanalyzer;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Extracts script URLs from an HTML page so missing files can be fetched. */
public final class HtmlScriptExtractor {

    private static final Pattern SCRIPT_TAG = Pattern.compile("<script\\b[^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern LINK_TAG = Pattern.compile("<link\\b[^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern SRC_ATTR = Pattern.compile(
            "\\bsrc\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))", Pattern.CASE_INSENSITIVE);
    private static final Pattern HREF_ATTR = Pattern.compile(
            "\\bhref\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))", Pattern.CASE_INSENSITIVE);
    private static final Pattern REL_ATTR = Pattern.compile(
            "\\brel\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))", Pattern.CASE_INSENSITIVE);

    private HtmlScriptExtractor() {
    }

    public static List<String> extract(String pageUrl, String html) {
        LinkedHashSet<String> urls = new LinkedHashSet<>();
        if (pageUrl == null || html == null || html.isEmpty()) {
            return List.of();
        }
        Matcher script = SCRIPT_TAG.matcher(html);
        while (script.find()) {
            String src = attribute(SRC_ATTR, script.group());
            String resolved = resolve(pageUrl, src);
            if (resolved != null) {
                urls.add(resolved);
            }
        }
        Matcher link = LINK_TAG.matcher(html);
        while (link.find()) {
            String tag = link.group();
            String rel = attribute(REL_ATTR, tag);
            if (rel == null) {
                continue;
            }
            String lower = rel.toLowerCase(Locale.ROOT);
            boolean scriptPreload = lower.contains("modulepreload")
                    || lower.contains("preload") && lower.contains("script");
            if (!scriptPreload) {
                continue;
            }
            String resolved = resolve(pageUrl, attribute(HREF_ATTR, tag));
            if (resolved != null) {
                urls.add(resolved);
            }
        }
        return new ArrayList<>(urls);
    }

    private static String attribute(Pattern pattern, String tag) {
        Matcher matcher = pattern.matcher(tag);
        if (!matcher.find()) {
            return null;
        }
        for (int i = 1; i <= matcher.groupCount(); i++) {
            if (matcher.group(i) != null) {
                return matcher.group(i);
            }
        }
        return null;
    }

    static String resolve(String pageUrl, String reference) {
        if (reference == null) {
            return null;
        }
        String value = reference.trim().replace("&amp;", "&");
        if (value.isEmpty() || value.startsWith("#")) {
            return null;
        }
        String lower = value.toLowerCase(Locale.ROOT);
        if (lower.startsWith("data:") || lower.startsWith("javascript:") || lower.startsWith("blob:")
                || lower.startsWith("mailto:") || lower.startsWith("about:")) {
            return null;
        }
        try {
            URI resolved = URI.create(pageUrl).resolve(value);
            if (resolved.getScheme() == null) {
                return null;
            }
            String text = resolved.toString();
            int fragment = text.indexOf('#');
            return fragment >= 0 ? text.substring(0, fragment) : text;
        } catch (RuntimeException ignored) {
            return null;
        }
    }
}
