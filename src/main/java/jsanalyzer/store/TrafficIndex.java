package jsanalyzer.store;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * HTTP methods Burp actually saw for request paths in this session.
 *
 * <p>Static analysis can only read a method where the code passes one
 * ({@code fetch(..., {method: 'POST'})}). For endpoints that appear as bare
 * strings the truth is in the traffic: when the browser (or Repeater) sends
 * {@code POST /api/v1/users}, that method is recorded here and shown next to
 * the endpoint. Bounded so a long session cannot grow it without limit.</p>
 */
public final class TrafficIndex {

    private static final int MAX_PATHS = 4000;

    private final Map<String, Set<String>> byPath = new LinkedHashMap<>(512, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Set<String>> eldest) {
            return size() > MAX_PATHS;
        }
    };

    /** Records one observed request. Cheap: called for every in-scope request. */
    public synchronized void record(String path, String method) {
        String normalized = normalizePath(path);
        if (normalized == null || method == null || method.isBlank()) {
            return;
        }
        byPath.computeIfAbsent(normalized, key -> new LinkedHashSet<>())
                .add(method.trim().toUpperCase(Locale.ROOT));
    }

    /** "POST" / "GET, POST" for an endpoint value (path, absolute or relative URL), or "". */
    public synchronized String methodsFor(String endpointValue) {
        String path = pathOf(endpointValue);
        if (path == null) {
            return "";
        }
        Set<String> methods = byPath.get(path);
        if (methods == null || methods.isEmpty()) {
            return "";
        }
        java.util.List<String> sorted = new java.util.ArrayList<>(methods);
        sorted.sort(String::compareTo);
        return String.join(", ", sorted);
    }

    public synchronized void clear() {
        byPath.clear();
    }

    public synchronized int size() {
        return byPath.size();
    }

    /** Path part of an endpoint value or request path; null when it is not path-like. */
    static String pathOf(String value) {
        if (value == null) {
            return null;
        }
        String candidate = value.trim();
        if (candidate.isEmpty()) {
            return null;
        }
        int scheme = candidate.indexOf("://");
        if (scheme > 0 || candidate.startsWith("//")) {
            try {
                return normalizePath(URI.create(candidate).getPath());
            } catch (RuntimeException ignored) {
                // Fall through to manual stripping.
            }
        }
        return normalizePath(candidate);
    }

    /** Strips query/fragment and trailing slashes; keeps case (paths are case-sensitive). */
    static String normalizePath(String path) {
        if (path == null) {
            return null;
        }
        String candidate = path.trim();
        int cut = indexOfAny(candidate, '?', '#');
        if (cut >= 0) {
            candidate = candidate.substring(0, cut);
        }
        if (candidate.isEmpty()) {
            return null;
        }
        if (!candidate.startsWith("/")) {
            candidate = "/" + candidate;
        }
        while (candidate.length() > 1 && candidate.endsWith("/")) {
            candidate = candidate.substring(0, candidate.length() - 1);
        }
        return candidate;
    }

    private static int indexOfAny(String value, char a, char b) {
        int first = value.indexOf(a);
        int second = value.indexOf(b);
        if (first < 0) {
            return second;
        }
        return second < 0 ? first : Math.min(first, second);
    }
}
