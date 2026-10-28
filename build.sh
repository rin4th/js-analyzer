#!/usr/bin/env bash
# Build the JS Analyzer Burp extension without Maven or Gradle.
#
#   ./build.sh          build dist/js-analyzer-burp.jar
#   ./build.sh test     build and run the analyzer + UI regression suites
#
# The Montoya API is compile-only: Burp provides it at runtime, so the jar
# contains only this extension's own classes.
set -euo pipefail
cd "$(dirname "$0")"

MONTOYA_VERSION="${MONTOYA_VERSION:-2024.7}"
MONTOYA_JAR="libs/montoya-api-${MONTOYA_VERSION}.jar"
MONTOYA_URL="https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/${MONTOYA_VERSION}/montoya-api-${MONTOYA_VERSION}.jar"

if [ ! -f "$MONTOYA_JAR" ]; then
  echo "Downloading Montoya API ${MONTOYA_VERSION}..."
  mkdir -p libs
  curl -fsSL -o "$MONTOYA_JAR" "$MONTOYA_URL"
fi

rm -rf build/classes build/test-classes dist
mkdir -p build/classes build/test-classes dist build/META-INF/services

# Extension classes (Java 17 bytecode so any recent Burp JRE can load them).
find src/main/java -name '*.java' > build/main-sources.txt
javac --release 17 -Xlint:all -cp "$MONTOYA_JAR" -d build/classes @build/main-sources.txt

printf 'jsanalyzer.BurpExtender\n' > build/META-INF/services/burp.api.montoya.BurpExtension
mkdir -p build/classes/META-INF/services
cp build/META-INF/services/burp.api.montoya.BurpExtension \
   build/classes/META-INF/services/burp.api.montoya.BurpExtension

printf 'Manifest-Version: 1.0\nImplementation-Title: JS Analyzer\nImplementation-Version: 1.3.1\nCreated-By: build.sh\n\n' \
  > build/MANIFEST.MF

jar --create --file dist/js-analyzer-burp.jar --manifest build/MANIFEST.MF -C build/classes .

if [ "${1:-build}" = "test" ]; then
  find src/test/java -name '*.java' > build/test-sources.txt
  javac --release 17 -cp "$MONTOYA_JAR:build/classes" -d build/test-classes @build/test-sources.txt
  java -Djava.awt.headless=true -cp "build/classes:build/test-classes" jsanalyzer.EngineTest
  java -Djava.awt.headless=true -cp "build/classes:build/test-classes:$MONTOYA_JAR" jsanalyzer.BurpHistoryImporterTest
  java -Djava.awt.headless=true -cp "build/classes:build/test-classes:$MONTOYA_JAR" jsanalyzer.ManualFetcherTest
  java -Djava.awt.headless=true -cp "build/classes:build/test-classes:$MONTOYA_JAR" jsanalyzer.HtmlScriptExtractorTest
  java -Djava.awt.headless=true -cp "build/classes:build/test-classes:$MONTOYA_JAR" jsanalyzer.ScriptAutoFetcherTest
  java -Djava.awt.headless=true -cp "build/classes:build/test-classes" jsanalyzer.ui.SourceExporterTest
  java -Djava.awt.headless=true -cp "build/classes:build/test-classes:$MONTOYA_JAR" jsanalyzer.UiSmokeTest
fi

echo
echo "Built dist/js-analyzer-burp.jar"
echo "Load it in Burp: Extensions > Installed > Add > Extension type: Java"
