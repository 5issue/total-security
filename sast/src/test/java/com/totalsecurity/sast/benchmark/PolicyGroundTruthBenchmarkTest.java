package com.totalsecurity.sast.benchmark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.detector.authn.Authn11PlaintextRefreshTokenStorageDetector;
import com.totalsecurity.sast.detector.authn.Svc05RawAuthTokenBrokerMessageDetector;
import com.totalsecurity.sast.finding.ChecklistFlowFinding;
import com.totalsecurity.sast.finding.FindingResult;
import com.totalsecurity.sast.pattern.authn.Authn06HardcodedSigningMaterialDetector;
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

/** Controlled policy benchmark, separate from the STEP 28 vulnerability benchmark. */
class PolicyGroundTruthBenchmarkTest {
    private static final Map<String, String> SUPPORTED_RULES = Map.of(
            Authn06HardcodedSigningMaterialDetector.RULE_ID,
            Authn06HardcodedSigningMaterialDetector.CHECKLIST_ID,
            Authn11PlaintextRefreshTokenStorageDetector.RULE_ID,
            Authn11PlaintextRefreshTokenStorageDetector.CHECKLIST_ID,
            Svc05RawAuthTokenBrokerMessageDetector.RULE_ID,
            Svc05RawAuthTokenBrokerMessageDetector.CHECKLIST_ID);

    @Test
    void measuresControlledPolicyFixturesThroughProductionProjectScanner() throws Exception {
        List<PolicyCase> cases = loadManifest(resource("benchmark/policy-ground-truth.tsv"));
        validateManifest(cases);

        ProjectScanResult scan = ProjectScanner.javaDefaults()
                .scan(resource("benchmark/policy/project"));
        assertEquals(
                ProjectScanStatus.COMPLETE,
                scan.status(),
                () -> "policy benchmark diagnostics: " + scan.diagnostics());

        Map<CaseKey, List<FindingResult>> actual = scan.findings().stream()
                .filter(finding -> SUPPORTED_RULES.containsKey(finding.ruleId()))
                .collect(Collectors.groupingBy(
                        finding -> new CaseKey(
                                normalize(scan.relativePath(finding.primaryLocation().file())),
                                finding.ruleId()),
                        LinkedHashMap::new,
                        Collectors.toList()));
        Set<CaseKey> expectedKeys = cases.stream()
                .map(PolicyCase::key)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        List<CaseKey> unmatched = actual.keySet().stream()
                .filter(key -> !expectedKeys.contains(key))
                .sorted(Comparator.comparing(CaseKey::sourceFile)
                        .thenComparing(CaseKey::ruleId))
                .toList();

        Map<String, Metrics> byRule = new LinkedHashMap<>();
        Metrics total = new Metrics();
        List<String> mismatches = new ArrayList<>();
        for (PolicyCase benchmarkCase : cases) {
            List<FindingResult> findings = actual.getOrDefault(benchmarkCase.key(), List.of());
            findings.forEach(finding -> assertChecklistIdentity(benchmarkCase, finding));
            if (benchmarkCase.expectedFindingCount() != findings.size()) {
                String mismatch = String.format(
                        Locale.ROOT,
                        "POLICY_BENCHMARK_CASE %s expected=%s expectedFindings=%d actualFindings=%d",
                        benchmarkCase.caseId(), benchmarkCase.expected(),
                        benchmarkCase.expectedFindingCount(), findings.size());
                mismatches.add(mismatch);
                System.out.println(mismatch);
            }
            if (benchmarkCase.expected() != Expected.UNSUPPORTED) {
                Metrics rule = byRule.computeIfAbsent(
                        benchmarkCase.ruleId(), ignored -> new Metrics());
                classify(benchmarkCase, findings, rule);
                classify(benchmarkCase, findings, total);
            }
        }
        for (CaseKey key : unmatched) {
            int count = actual.get(key).size();
            String mismatch = String.format(
                    Locale.ROOT,
                    "POLICY_BENCHMARK_UNMATCHED source=%s rule=%s findings=%d",
                    key.sourceFile(), key.ruleId(), count);
            mismatches.add(mismatch);
            System.out.println(mismatch);
            byRule.computeIfAbsent(key.ruleId(), ignored -> new Metrics()).fp += count;
            total.fp += count;
        }

        assertEquals(SUPPORTED_RULES.keySet(), byRule.keySet());
        assertMetrics(total, 9, 0, 0, 9);
        byRule.values().forEach(metrics -> assertMetrics(metrics, 3, 0, 0, 3));
        printMetrics("TOTAL", total);
        byRule.entrySet().stream().sorted(Map.Entry.comparingByKey())
                .forEach(entry -> printMetrics(entry.getKey(), entry.getValue()));
        assertTrue(
                mismatches.isEmpty(),
                () -> String.join(System.lineSeparator(), mismatches)
                        + System.lineSeparator() + "diagnostics=" + scan.diagnostics());
    }

    private static void assertChecklistIdentity(PolicyCase benchmarkCase, FindingResult finding) {
        assertEquals(benchmarkCase.ruleId(), finding.ruleId());
        if (finding instanceof ChecklistFlowFinding checklistFinding) {
            assertEquals(benchmarkCase.checklistId(), checklistFinding.checklistId());
        } else {
            assertTrue(
                    finding.evidence().contains(benchmarkCase.checklistId()),
                    () -> benchmarkCase.caseId() + ": " + finding.evidence());
        }
    }

    private static void validateManifest(List<PolicyCase> cases) {
        assertEquals(18, cases.size());
        assertEquals(cases.size(), cases.stream().map(PolicyCase::caseId).distinct().count());
        assertEquals(SUPPORTED_RULES.keySet(), cases.stream()
                .map(PolicyCase::ruleId)
                .collect(Collectors.toSet()));
        assertEquals(0, cases.stream()
                .filter(item -> item.expected() == Expected.UNSUPPORTED)
                .count());
        for (Map.Entry<String, String> rule : SUPPORTED_RULES.entrySet()) {
            List<PolicyCase> ruleCases = cases.stream()
                    .filter(item -> item.ruleId().equals(rule.getKey()))
                    .toList();
            assertEquals(6, ruleCases.size(), rule.getKey());
            assertEquals(3, ruleCases.stream()
                    .filter(item -> item.expected() == Expected.POSITIVE)
                    .count(), rule.getKey());
            assertEquals(3, ruleCases.stream()
                    .filter(item -> item.expected() == Expected.NEGATIVE)
                    .count(), rule.getKey());
        }
        for (PolicyCase benchmarkCase : cases) {
            assertEquals(
                    SUPPORTED_RULES.get(benchmarkCase.ruleId()),
                    benchmarkCase.checklistId(),
                    benchmarkCase.caseId());
            assertEquals(
                    benchmarkCase.expected() == Expected.POSITIVE ? 1 : 0,
                    benchmarkCase.expectedFindingCount(),
                    benchmarkCase.caseId());
            assertTrue(Set.of("L1", "L2", "L3", "L4")
                    .contains(benchmarkCase.complexity()));
            assertTrue(!benchmarkCase.rationale().isBlank());
        }
    }

    private static void classify(
            PolicyCase benchmarkCase, List<FindingResult> findings, Metrics metrics) {
        if (benchmarkCase.expected() == Expected.POSITIVE) {
            if (findings.isEmpty()) {
                metrics.fn++;
            } else {
                metrics.tp++;
            }
        } else if (benchmarkCase.expected() == Expected.NEGATIVE) {
            if (findings.isEmpty()) {
                metrics.tn++;
            } else {
                metrics.fp++;
            }
        }
    }

    private static void assertMetrics(
            Metrics metrics, int tp, int fp, int fn, int tn) {
        assertEquals(tp, metrics.tp);
        assertEquals(fp, metrics.fp);
        assertEquals(fn, metrics.fn);
        assertEquals(tn, metrics.tn);
    }

    private static void printMetrics(String name, Metrics metrics) {
        System.out.printf(
                Locale.ROOT,
                "POLICY BENCHMARK controlled policy benchmark fixtures %s "
                        + "TP=%d FP=%d FN=%d TN=%d precision=%s recall=%s f1=%s%n",
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

    private static List<PolicyCase> loadManifest(Path manifest) throws Exception {
        List<String> lines = Files.readAllLines(manifest, StandardCharsets.UTF_8);
        assertTrue(!lines.isEmpty());
        assertEquals(
                "caseId\tchecklistId\truleId\texpected\tsourceFile\t"
                        + "expectedFindingCount\tcomplexity\trationale",
                lines.getFirst());
        List<PolicyCase> cases = new ArrayList<>();
        for (String line : lines.subList(1, lines.size())) {
            if (line.isBlank()) {
                continue;
            }
            String[] columns = line.split("\\t", -1);
            assertEquals(8, columns.length, line);
            cases.add(new PolicyCase(
                    columns[0], columns[1], columns[2], Expected.valueOf(columns[3]),
                    normalize(Path.of(columns[4])), Integer.parseInt(columns[5]),
                    columns[6], columns[7]));
        }
        return List.copyOf(cases);
    }

    private static Path resource(String name) throws URISyntaxException {
        var resource = PolicyGroundTruthBenchmarkTest.class.getClassLoader().getResource(name);
        if (resource == null) {
            throw new IllegalStateException("Policy benchmark resource not found: " + name);
        }
        return Path.of(resource.toURI());
    }

    private static String normalize(Path path) {
        return path.toString().replace('\\', '/');
    }

    private enum Expected {
        POSITIVE,
        NEGATIVE,
        UNSUPPORTED
    }

    private record CaseKey(String sourceFile, String ruleId) {}

    private record PolicyCase(
            String caseId,
            String checklistId,
            String ruleId,
            Expected expected,
            String sourceFile,
            int expectedFindingCount,
            String complexity,
            String rationale) {
        private CaseKey key() {
            return new CaseKey(sourceFile, ruleId);
        }
    }

    private static final class Metrics {
        private int tp;
        private int fp;
        private int fn;
        private int tn;
    }
}
