package jsanalyzer;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import jsanalyzer.store.AnalysisStore;
import jsanalyzer.ui.AnalyzerTab;

/**
 * Entry point. Registers the "JS Analyzer" suite tab and a passive HTTP
 * handler that analyzes in-scope JavaScript responses once each.
 */
public final class BurpExtender implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("JS Analyzer");

        AnalysisStore store = new AnalysisStore();
        ScriptAutoFetcher autoFetcher = new ScriptAutoFetcher(api, store);
        AnalyzerTab tab = new AnalyzerTab(api, store, autoFetcher);
        api.userInterface().registerSuiteTab("JS Analyzer", tab);
        TrafficListener listener = new TrafficListener(api, store, autoFetcher);
        api.http().registerHttpHandler(listener);
        api.extension().registerUnloadingHandler(() -> {
            autoFetcher.shutdown();
            store.shutdown();
            api.logging().logToOutput("JS Analyzer unloaded");
        });

        api.logging().logToOutput("JS Analyzer loaded — in-scope JavaScript responses are collected "
                + "and analyzed once per file.");
    }
}
