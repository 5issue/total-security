package com.totalsecurity.sast.benchmark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.detector.command.CommandInjectionDetector;
import com.totalsecurity.sast.detector.deserialization.InsecureDeserializationDetector;
import com.totalsecurity.sast.detector.ldap.LdapInjectionDetector;
import com.totalsecurity.sast.detector.path.PathTraversalDetector;
import com.totalsecurity.sast.detector.redirect.OpenRedirectDetector;
import com.totalsecurity.sast.detector.sql.SqlInjectionDetector;
import com.totalsecurity.sast.detector.ssrf.SsrfDetector;
import com.totalsecurity.sast.detector.upload.UnrestrictedFileUploadDetector;
import com.totalsecurity.sast.detector.xss.XssDetector;
import com.totalsecurity.sast.detector.xxe.XxeDetector;
import com.totalsecurity.sast.finding.FindingResult;
import com.totalsecurity.sast.pattern.credential.HardcodedCredentialDetector;
import com.totalsecurity.sast.runner.ProjectScanResult;
import com.totalsecurity.sast.runner.ProjectScanStatus;
import com.totalsecurity.sast.runner.ProjectScanner;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/** Controlled, case-level ground-truth benchmark over the production project scanner. */
class GroundTruthBenchmarkTest {
    private static final Map<String, RuleMetadata> SUPPORTED_RULES = Map.ofEntries(
            rule(SqlInjectionDetector.RULE_ID, SqlInjectionDetector.VULNERABILITY_TYPE,
                    SqlInjectionDetector.CWE),
            rule(CommandInjectionDetector.RULE_ID, CommandInjectionDetector.VULNERABILITY_TYPE,
                    CommandInjectionDetector.CWE),
            rule(PathTraversalDetector.RULE_ID, PathTraversalDetector.VULNERABILITY_TYPE,
                    PathTraversalDetector.CWE),
            rule(SsrfDetector.RULE_ID, SsrfDetector.VULNERABILITY_TYPE, SsrfDetector.CWE),
            rule(LdapInjectionDetector.RULE_ID, LdapInjectionDetector.VULNERABILITY_TYPE,
                    LdapInjectionDetector.CWE),
            rule(XssDetector.RULE_ID, XssDetector.VULNERABILITY_TYPE, XssDetector.CWE),
            rule(XxeDetector.RULE_ID, XxeDetector.VULNERABILITY_TYPE, XxeDetector.CWE),
            rule(OpenRedirectDetector.RULE_ID, OpenRedirectDetector.VULNERABILITY_TYPE,
                    OpenRedirectDetector.CWE),
            rule(InsecureDeserializationDetector.RULE_ID,
                    InsecureDeserializationDetector.VULNERABILITY_TYPE,
                    InsecureDeserializationDetector.CWE),
            rule(UnrestrictedFileUploadDetector.RULE_ID,
                    UnrestrictedFileUploadDetector.VULNERABILITY_TYPE,
                    UnrestrictedFileUploadDetector.CWE),
            rule(HardcodedCredentialDetector.RULE_ID,
                    HardcodedCredentialDetector.VULNERABILITY_TYPE,
                    HardcodedCredentialDetector.CWE));

    @Test
    void measuresControlledGroundTruthByRuleCweAndSourceFile() throws Exception {
        List<GroundTruthCase> cases = loadManifest(resource("benchmark/ground-truth.tsv"));
        validateManifest(cases);

        ProjectScanResult scan = ProjectScanner.javaDefaults()
                .scan(resource("benchmark/project"));
        assertEquals(ProjectScanStatus.COMPLETE, scan.status());
        assertTrue(scan.diagnostics().isEmpty(), () -> "benchmark diagnostics: " + scan.diagnostics());

        Map<CaseKey, List<FindingResult>> actual = scan.findings().stream()
                .collect(Collectors.groupingBy(
                        finding -> new CaseKey(
                                normalize(scan.relativePath(finding.primaryLocation().file())),
                                finding.ruleId(),
                                finding.cwe()),
                        LinkedHashMap::new,
                        Collectors.toList()));
        Set<CaseKey> expectedKeys = cases.stream()
                .map(GroundTruthCase::key)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        List<CaseKey> unmatched = actual.keySet().stream()
                .filter(key -> !expectedKeys.contains(key))
                .sorted(Comparator.comparing(CaseKey::sourceFile)
                        .thenComparing(CaseKey::ruleId))
                .toList();

        Map<String, Metrics> byRule = new LinkedHashMap<>();
        Metrics total = new Metrics();
        List<String> mismatches = new ArrayList<>();
        for (GroundTruthCase benchmarkCase : cases) {
            List<FindingResult> findings = actual.getOrDefault(benchmarkCase.key(), List.of());
            findings.forEach(finding -> {
                assertEquals(benchmarkCase.vulnerability(), finding.vulnerabilityType());
                assertEquals(benchmarkCase.cwe(), finding.cwe());
            });
            if (benchmarkCase.expectedFindingCount() != findings.size()) {
                String mismatch = String.format(
                        Locale.ROOT,
                        "BENCHMARK_CASE %s expected=%s expectedFindings=%d actualFindings=%d",
                        benchmarkCase.caseId(), benchmarkCase.expected(),
                        benchmarkCase.expectedFindingCount(), findings.size());
                mismatches.add(mismatch);
                System.out.println(mismatch);
            }
            Metrics category = byRule.computeIfAbsent(
                    benchmarkCase.ruleId(), ignored -> new Metrics());
            classify(benchmarkCase, findings, category);
            classify(benchmarkCase, findings, total);
        }
        for (CaseKey key : unmatched) {
            int count = actual.get(key).size();
            System.out.printf(
                    Locale.ROOT,
                    "BENCHMARK_UNMATCHED source=%s rule=%s cwe=%s findings=%d%n",
                    key.sourceFile(), key.ruleId(), key.cwe(), count);
            mismatches.add(String.format(
                    Locale.ROOT,
                    "BENCHMARK_UNMATCHED source=%s rule=%s cwe=%s findings=%d",
                    key.sourceFile(), key.ruleId(), key.cwe(), count));
            byRule.computeIfAbsent(key.ruleId(), ignored -> new Metrics()).fp += count;
            total.fp += count;
        }

        assertEquals(SUPPORTED_RULES.keySet(), byRule.keySet());
        printMetrics("TOTAL", total);
        byRule.entrySet().stream().sorted(Map.Entry.comparingByKey())
                .forEach(entry -> printMetrics(entry.getKey(), entry.getValue()));
        assertTrue(mismatches.isEmpty(), () -> String.join(System.lineSeparator(), mismatches));
    }

    private static void validateManifest(List<GroundTruthCase> cases) {
        assertEquals(23, cases.size());
        assertEquals(cases.size(), cases.stream().map(GroundTruthCase::caseId).distinct().count());
        assertEquals(SUPPORTED_RULES.keySet(), cases.stream()
                .map(GroundTruthCase::ruleId)
                .collect(Collectors.toSet()));
        for (GroundTruthCase benchmarkCase : cases) {
            RuleMetadata metadata = SUPPORTED_RULES.get(benchmarkCase.ruleId());
            assertEquals(metadata.vulnerability(), benchmarkCase.vulnerability(), benchmarkCase.caseId());
            assertEquals(metadata.cwe(), benchmarkCase.cwe(), benchmarkCase.caseId());
            assertEquals(
                    benchmarkCase.expected() == Expected.VULNERABLE ? 1 : 0,
                    benchmarkCase.expectedFindingCount(),
                    benchmarkCase.caseId());
            assertTrue(Set.of("L1", "L2", "L3", "L4").contains(benchmarkCase.complexity()));
            assertTrue(!benchmarkCase.rationale().isBlank());
        }
    }

    private static void classify(
            GroundTruthCase benchmarkCase, List<FindingResult> findings, Metrics metrics) {
        if (benchmarkCase.expected() == Expected.VULNERABLE) {
            if (findings.isEmpty()) {
                metrics.fn++;
            } else {
                metrics.tp++;
            }
        } else if (findings.isEmpty()) {
            metrics.tn++;
        } else {
            metrics.fp++;
        }
    }

    private static void printMetrics(String name, Metrics metrics) {
        System.out.printf(
                Locale.ROOT,
                "BENCHMARK %s TP=%d FP=%d FN=%d TN=%d precision=%s recall=%s f1=%s%n",
                name, metrics.tp, metrics.fp, metrics.fn, metrics.tn,
                rate(metrics.tp, metrics.tp + metrics.fp),
                rate(metrics.tp, metrics.tp + metrics.fn),
                f1(metrics));
    }

    private static String f1(Metrics metrics) {
        int precisionDenominator = metrics.tp + metrics.fp;
        int recallDenominator = metrics.tp + metrics.fn;
        if (precisionDenominator == 0 || recallDenominator == 0) {
            return "N/A";
        }
        double precision = (double) metrics.tp / precisionDenominator;
        double recall = (double) metrics.tp / recallDenominator;
        return precision + recall == 0.0
                ? "N/A"
                : String.format(Locale.ROOT, "%.4f", 2.0 * precision * recall / (precision + recall));
    }

    private static String rate(int numerator, int denominator) {
        return denominator == 0
                ? "N/A"
                : String.format(Locale.ROOT, "%.4f", (double) numerator / denominator);
    }

    private static List<GroundTruthCase> loadManifest(Path manifest) throws Exception {
        List<String> lines = Files.readAllLines(manifest, StandardCharsets.UTF_8);
        assertTrue(!lines.isEmpty());
        assertEquals(
                "caseId\truleId\tvulnerability\tcwe\texpected\tsourceFile\t"
                        + "expectedFindingCount\tcomplexity\trationale",
                lines.getFirst());
        List<GroundTruthCase> cases = new ArrayList<>();
        for (String line : lines.subList(1, lines.size())) {
            if (line.isBlank()) {
                continue;
            }
            String[] columns = line.split("\\t", -1);
            assertEquals(9, columns.length, line);
            cases.add(new GroundTruthCase(
                    columns[0], columns[1], columns[2], columns[3],
                    Expected.valueOf(columns[4]), normalize(Path.of(columns[5])),
                    Integer.parseInt(columns[6]), columns[7], columns[8]));
        }
        return List.copyOf(cases);
    }

    private static Path resource(String name) throws URISyntaxException {
        var resource = GroundTruthBenchmarkTest.class.getClassLoader().getResource(name);
        if (resource == null) {
            throw new IllegalStateException("Benchmark resource not found: " + name);
        }
        return Path.of(resource.toURI());
    }

    private static String normalize(Path path) {
        return path.toString().replace('\\', '/');
    }

    private static Map.Entry<String, RuleMetadata> rule(
            String id, String vulnerability, String cwe) {
        return Map.entry(id, new RuleMetadata(vulnerability, cwe));
    }

    private enum Expected {
        VULNERABLE,
        SAFE
    }

    private record RuleMetadata(String vulnerability, String cwe) {}

    private record CaseKey(String sourceFile, String ruleId, String cwe) {}

    private record GroundTruthCase(
            String caseId,
            String ruleId,
            String vulnerability,
            String cwe,
            Expected expected,
            String sourceFile,
            int expectedFindingCount,
            String complexity,
            String rationale) {
        private CaseKey key() {
            return new CaseKey(sourceFile, ruleId, cwe);
        }
    }

    private static final class Metrics {
        private int tp;
        private int fp;
        private int fn;
        private int tn;
    }
}
