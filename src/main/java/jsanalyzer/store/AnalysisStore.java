package jsanalyzer.store;

import jsanalyzer.engine.Analyzer;
import jsanalyzer.model.AnalysisResult;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

/**
 * Collects in-scope JavaScript responses and analyzes each unique file once.
 * Files are keyed by URL without the query string, so cache-busting parameters
 * do not create duplicates. If the same URL later returns different content,
 * the entry is analyzed again and updated in place.
 */
public final class AnalysisStore {

    public interface Listener {
        void filesChanged();
    }

    private final Map<String, JsFile> files = new LinkedHashMap<>();
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();
    private final ExecutorService executor;
    private final TrafficIndex traffic = new TrafficIndex();
    private volatile SourceProvider sourceProvider;

    public boolean contains(String url) {
        synchronized (files) {
            return files.containsKey(normalizeKey(url));
        }
    }

    /** Records an in-scope request so endpoints can show methods Burp actually saw. */
    public void recordRequest(String path, String method) {
        traffic.record(path, method);
    }

    /** "POST" / "GET, POST" observed for an endpoint value, or "". */
    public String observedMethods(String endpointValue) {
        return traffic.methodsFor(endpointValue);
    }

    public int observedPathCount() {
        return traffic.size();
    }

    /** Provides the code on demand for re-analysis and source export. */
    public void setSourceProvider(SourceProvider provider) {
        this.sourceProvider = provider;
    }

    public SourceProvider sourceProvider() {
        return sourceProvider;
    }

    public AnalysisStore() {
        ThreadFactory factory = runnable -> {
            Thread thread = new Thread(runnable, "js-analyzer-worker");
            thread.setDaemon(true);
            thread.setPriority(Thread.MIN_PRIORITY + 1);
            return thread;
        };
        this.executor = Executors.newFixedThreadPool(2, factory);
    }

    public void addListener(Listener listener) {
        listeners.add(listener);
    }

    public void removeListener(Listener listener) {
        listeners.remove(listener);
    }

    /** Submits a response. Returns the file entry, or the existing entry when skipped. */
    public JsFile submit(String url, String body, int statusCode, String contentType) {
        if (url == null || body == null || body.isEmpty()) {
            return null;
        }
        String key = normalizeKey(url);
        String hash = contentHash(body);
        int bytes = utf8Length(body);
        JsFile file;
        boolean analyze = true;
        synchronized (files) {
            file = files.get(key);
            if (file != null) {
                file.hits++;
                file.lastSeen = System.currentTimeMillis();
                if (hash.equals(file.contentHash)) {
                    // Same JavaScript file: already analyzed, nothing to do.
                    analyze = false;
                } else {
                    file.contentHash = hash;
                    file.statusCode = statusCode;
                    file.contentType = contentType;
                    file.size = bytes;
                    file.status = "Queued";
                    file.error = null;
                    file.result = null;
                }
            } else {
                file = new JsFile(key, url, hostOf(url), statusCode, contentType, bytes, hash);
                files.put(key, file);
            }
        }
        if (!analyze) {
            notifyListeners();
            return file;
        }
        analyzeAsync(file, body);
        return file;
    }

    private void analyzeAsync(JsFile file, String body) {
        file.status = "Queued";
        notifyListeners();
        executor.submit(() -> {
            file.status = "Analyzing";
            notifyListeners();
            try {
                AnalysisResult result = Analyzer.analyze(body);
                file.result = result;
                file.status = "Analyzed";
            } catch (Throwable throwable) {
                file.error = throwable.getClass().getSimpleName() + ": " + throwable.getMessage();
                file.status = "Error";
            }
            notifyListeners();
        });
    }

    public List<JsFile> snapshot() {
        synchronized (files) {
            return new ArrayList<>(files.values());
        }
    }

    public int size() {
        synchronized (files) {
            return files.size();
        }
    }

    public void remove(JsFile file) {
        if (file == null) {
            return;
        }
        synchronized (files) {
            files.remove(file.key);
        }
        notifyListeners();
    }

    public void clear() {
        synchronized (files) {
            files.clear();
        }
        traffic.clear();
        notifyListeners();
    }

    /**
     * Re-runs the analysis for a file by fetching its code again (the body is
     * not retained after the first analysis). Failures are recorded on the
     * entry instead of throwing.
     */
    public void reanalyze(JsFile file) {
        if (file == null) {
            return;
        }
        SourceProvider provider = sourceProvider;
        file.status = "Queued";
        file.error = null;
        file.result = null;
        notifyListeners();
        if (provider == null) {
            file.status = "Error";
            file.error = "No source provider: re-analysis needs Burp's HTTP stack";
            notifyListeners();
            return;
        }
        executor.submit(() -> {
            file.status = "Analyzing";
            notifyListeners();
            try {
                String body = provider.fetch(file.url);
                if (body == null || body.isEmpty()) {
                    throw new java.io.IOException("empty response body");
                }
                file.contentHash = contentHash(body);
                file.size = utf8Length(body);
                AnalysisResult result = Analyzer.analyze(body);
                file.result = result;
                file.status = "Analyzed";
            } catch (Throwable throwable) {
                file.error = throwable.getClass().getSimpleName() + ": " + throwable.getMessage();
                file.status = "Error";
            }
            notifyListeners();
        });
    }

    public void shutdown() {
        executor.shutdownNow();
    }

    private void notifyListeners() {
        for (Listener listener : listeners) {
            try {
                listener.filesChanged();
            } catch (RuntimeException ignored) {
                // A failing UI listener must never break traffic processing.
            }
        }
    }

    public static String normalizeKey(String url) {
        try {
            java.net.URI uri = java.net.URI.create(url);
            String scheme = uri.getScheme() == null ? "http" : uri.getScheme().toLowerCase(Locale.ROOT);
            String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
            int port = uri.getPort();
            String path = uri.getPath() == null || uri.getPath().isEmpty() ? "/" : uri.getPath();
            return scheme + "://" + host + (port > 0 ? ":" + port : "") + path;
        } catch (RuntimeException ignored) {
            int query = url.indexOf('?');
            int fragment = url.indexOf('#');
            int cut = query < 0 ? fragment : fragment < 0 ? query : Math.min(query, fragment);
            return cut < 0 ? url : url.substring(0, cut);
        }
    }

    static String hostOf(String url) {
        try {
            String host = java.net.URI.create(url).getHost();
            return host == null ? "" : host;
        } catch (RuntimeException ignored) {
            return "";
        }
    }

    /** Cheap content fingerprint; only used to detect whether a file changed. */
    public static String contentHash(String body) {
        long hash = 1125899906842597L;
        int step = body.length() > 500_000 ? 3 : 1;
        for (int i = 0; i < body.length(); i += step) {
            hash = 31 * hash + body.charAt(i);
        }
        return Integer.toHexString(body.hashCode()) + ":" + Long.toHexString(hash) + ":" + body.length();
    }

    /** Byte length of the body as UTF-8, without copying it. */
    static int utf8Length(String body) {
        int bytes = body.length();
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            if (c < 0x80) {
                continue;
            }
            if (c < 0x800) {
                bytes += 1;
            } else if (Character.isHighSurrogate(c)) {
                bytes += 2;
                i++;
            } else if (Character.isLowSurrogate(c)) {
                continue;
            } else {
                bytes += 2;
            }
        }
        return bytes;
    }

    public List<JsFile> analyzed() {
        List<JsFile> analyzed = new ArrayList<>();
        for (JsFile file : snapshot()) {
            if ("Analyzed".equals(file.status)) {
                analyzed.add(file);
            }
        }
        return analyzed;
    }

    public Map<String, Integer> counts() {
        Map<String, Integer> counts = new LinkedHashMap<>();
        int analyzed = 0;
        int queued = 0;
        int errors = 0;
        int duplicates = 0;
        for (JsFile file : snapshot()) {
            switch (file.status) {
                case "Analyzed":
                    analyzed++;
                    break;
                case "Queued":
                case "Analyzing":
                    queued++;
                    break;
                default:
                    errors++;
                    break;
            }
            duplicates += Math.max(0, file.hits - 1);
        }
        counts.put("total", size());
        counts.put("analyzed", analyzed);
        counts.put("queued", queued);
        counts.put("errors", errors);
        counts.put("duplicates", duplicates);
        return Collections.unmodifiableMap(counts);
    }
}
