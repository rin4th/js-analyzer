package jsanalyzer;

import burp.api.montoya.MontoyaApi;
import jsanalyzer.store.AnalysisStore;

import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Automatically fetches script URLs discovered in in-scope HTML pages when the
 * file is not already in the list. Fetches go through Burp's HTTP stack, which
 * bypasses browser and service-worker caches that hide responses from the
 * proxy — the usual reason a script appears in DevTools but not in Burp.
 */
public final class ScriptAutoFetcher {

    public interface Fetcher {
        ManualFetcher.Result fetch(String url);
    }

    private static final int MAX_PER_PAGE = 60;
    private static final int MAX_PENDING = 200;
    private static final int MAX_HTML_BYTES = 2 * 1024 * 1024;

    private final MontoyaApi api;
    private final AnalysisStore store;
    private final Fetcher fetcher;
    private final Set<String> attempted = ConcurrentHashMap.newKeySet();
    private final AtomicInteger pending = new AtomicInteger();
    private final AtomicInteger loggedFailures = new AtomicInteger();
    private final ExecutorService pool;
    private volatile boolean enabled = true;

    public ScriptAutoFetcher(MontoyaApi api, AnalysisStore store) {
        this(api, store, url -> ManualFetcher.fetch(api, store, url));
    }

    ScriptAutoFetcher(MontoyaApi api, AnalysisStore store, Fetcher fetcher) {
        this.api = api;
        this.store = store;
        this.fetcher = fetcher;
        this.pool = Executors.newFixedThreadPool(2, runnable -> {
            Thread thread = new Thread(runnable, "js-analyzer-autofetch");
            thread.setDaemon(true);
            return thread;
        });
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    /** Queues missing scripts found in an HTML page; returns how many were queued. */
    public int considerPage(String pageUrl, String html) {
        if (!enabled || pageUrl == null || html == null || html.isEmpty()
                || html.length() > MAX_HTML_BYTES) {
            return 0;
        }
        int queued = 0;
        for (String url : HtmlScriptExtractor.extract(pageUrl, html)) {
            if (queued >= MAX_PER_PAGE || pending.get() >= MAX_PENDING) {
                break;
            }
            if (obviousNonScript(url) || store.contains(url) || !inScope(url)) {
                continue;
            }
            String key = AnalysisStore.normalizeKey(url);
            if (!attempted.add(key)) {
                continue;
            }
            pending.incrementAndGet();
            pool.submit(() -> {
                try {
                    ManualFetcher.Result result = fetcher.fetch(url);
                    if (result != null && !result.ok && loggedFailures.incrementAndGet() <= 20) {
                        api.logging().logToOutput("JS Analyzer auto-fetch skipped: " + url
                                + " — " + result.message);
                    }
                } catch (RuntimeException ignored) {
                    // A failed auto-fetch must never affect Burp traffic.
                } finally {
                    pending.decrementAndGet();
                }
            });
            queued++;
        }
        return queued;
    }

    public int queuedCount() {
        return pending.get();
    }

    public void shutdown() {
        pool.shutdownNow();
    }

    private boolean inScope(String url) {
        try {
            return api.scope().isInScope(url);
        } catch (RuntimeException exception) {
            return false;
        }
    }

    private static boolean obviousNonScript(String url) {
        String lower = url.toLowerCase(Locale.ROOT);
        int query = lower.indexOf('?');
        String path = query >= 0 ? lower.substring(0, query) : lower;
        return path.endsWith(".css") || path.endsWith(".png") || path.endsWith(".jpg")
                || path.endsWith(".jpeg") || path.endsWith(".gif") || path.endsWith(".svg")
                || path.endsWith(".webp") || path.endsWith(".ico") || path.endsWith(".woff")
                || path.endsWith(".woff2") || path.endsWith(".ttf") || path.endsWith(".map");
    }
}
