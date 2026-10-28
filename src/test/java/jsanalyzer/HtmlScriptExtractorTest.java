package jsanalyzer;

import java.util.List;

/** Tests script-URL extraction from HTML pages. */
public final class HtmlScriptExtractorTest {

    private static int passed;
    private static int failed;

    public static void main(String[] args) {
        String page = "https://www.unipin.com/id/mobile-legends";
        String html = "<html><head>\n"
                + "  <script data-cookieconsent=\"ignore\" src=\"/js/app.v5.js?id=54d433\" "
                + "type=\"text/javascript\"></script>\n"
                + "  <script src='js/vendor/splide.min.js'></script>\n"
                + "  <script src=\"//cdn.example.test/a.js?v=1&amp;x=2\"></script>\n"
                + "  <script src=\"data:text/javascript,alert(1)\"></script>\n"
                + "  <script src=\"/js/app.v5.js?id=54d433\"></script>\n"
                + "  <link rel=\"modulepreload\" href=\"/js/chunk.js\">\n"
                + "  <link rel=\"stylesheet\" href=\"/css/app.css\">\n"
                + "</head></html>";

        List<String> urls = HtmlScriptExtractor.extract(page, html);
        check("scripts.count", 4, urls.size());
        check("scripts.app", "https://www.unipin.com/js/app.v5.js?id=54d433", urls.get(0));
        check("scripts.relative", "https://www.unipin.com/id/js/vendor/splide.min.js", urls.get(1));
        check("scripts.protocolRelative", "https://cdn.example.test/a.js?v=1&x=2", urls.get(2));
        check("scripts.modulepreload", "https://www.unipin.com/js/chunk.js", urls.get(3));
        check("scripts.dedupe", true, urls.stream().filter(u -> u.contains("app.v5.js")).count() == 1);

        check("scripts.resolveRoot", "https://www.unipin.com/a.js",
                HtmlScriptExtractor.resolve("https://www.unipin.com/x/y", "/a.js"));
        check("scripts.resolveHash", null,
                HtmlScriptExtractor.resolve("https://www.unipin.com/a", "#frag"));
        check("scripts.resolveJavascript", null,
                HtmlScriptExtractor.resolve("https://www.unipin.com/a", "javascript:void(0)"));
        check("scripts.emptyHtml", 0, HtmlScriptExtractor.extract(page, "").size());

        System.out.println("passed: " + passed + ", failed: " + failed);
        if (failed > 0) {
            System.exit(1);
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
