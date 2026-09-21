package com.totalsecurity.sast.pattern.credential;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.finding.FindingResult;
import com.totalsecurity.sast.finding.FindingSeverity;
import com.totalsecurity.sast.finding.PatternFinding;
import com.totalsecurity.sast.finding.PatternOccurrenceKind;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.java.extractor.JavaSemanticExtractor;
import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import com.totalsecurity.sast.pattern.PatternAnalysis;
import com.totalsecurity.sast.pattern.authn.Authn06HardcodedSigningMaterialDetector;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class HardcodedCredentialDetectorTest {
    private static JavaFileInfo file;
    private static List<PatternFinding> findings;

    @BeforeAll
    static void analyzeFixture() throws Exception {
        try (JavaSourceParser parser = new JavaSourceParser();
                ParsedJavaFile parsed = parser.parse(fixturePath())) {
            assertFalse(parsed.hasSyntaxErrors());
            file = new JavaSemanticExtractor().extract(parsed);
        }
        findings = PatternAnalysis.javaDefaults().analyze(file);
    }

    @Test
    void fieldPasswordLiteralIsDetected() {
        PatternFinding finding = only("password", PatternOccurrenceKind.FIELD_DECLARATION);
        assertEquals(4, finding.primaryLocation().startLine());
    }

    @ParameterizedTest(name = "detects local sensitive identifier {0}")
    @MethodSource("sensitiveLocalIdentifiers")
    void localSensitiveStringLiteralIsDetected(String identifier) {
        assertEquals(1, matching(identifier, PatternOccurrenceKind.LOCAL_DECLARATION).size());
    }

    private static Stream<String> sensitiveLocalIdentifiers() {
        return Stream.of(
                "password",
                "passwd",
                "pwd",
                "secretKey",
                "clientSecret",
                "apiKey",
                "api_key",
                "accessToken",
                "authToken");
    }

    @Test
    void laterLiteralAssignmentIsDetected() {
        PatternFinding finding = only("password", PatternOccurrenceKind.ASSIGNMENT);
        assertEquals(44, finding.primaryLocation().startLine());
    }

    @ParameterizedTest(name = "does not detect non-literal initializer in {0}")
    @MethodSource("nonLiteralSensitiveInitializers")
    void nonLiteralSensitiveInitializerIsNotDetected(String identifier) {
        assertTrue(findings.stream()
                .filter(finding -> finding.identifier().equals(identifier))
                .noneMatch(finding -> Set.of(54, 58, 62, 66, 89)
                        .contains(finding.primaryLocation().startLine())));
    }

    private static Stream<Arguments> nonLiteralSensitiveInitializers() {
        return Stream.of(
                Arguments.of("password"),
                Arguments.of("apiKey"),
                Arguments.of("token"),
                Arguments.of("secret"),
                Arguments.of("privateKey"));
    }

    @Test
    void normalStringLiteralVariableIsNotDetected() {
        assertTrue(findings.stream().noneMatch(finding -> finding.identifier().equals("displayName")));
    }

    @Test
    void emptySensitiveStringIsNotDetected() {
        assertTrue(findings.stream().noneMatch(finding -> finding.primaryLocation().startLine() == 74));
    }

    @Test
    void whitespaceOnlySensitiveStringIsNotDetected() {
        assertTrue(findings.stream().noneMatch(finding -> finding.primaryLocation().startLine() == 78));
    }

    @ParameterizedTest(name = "does not substring-match {0}")
    @MethodSource("vaguelyRelatedIdentifiers")
    void vaguelyRelatedIdentifierIsNotDetected(String identifier) {
        assertTrue(findings.stream().noneMatch(finding -> finding.identifier().equals(identifier)));
    }

    private static Stream<String> vaguelyRelatedIdentifiers() {
        return Stream.of("tokenCount", "passwordEnabled", "secretary", "apiKeyEnabled");
    }

    @Test
    void findingMetadataIsHardcodedCredentialCwe798High() {
        PatternFinding finding = findings.getFirst();
        assertEquals(HardcodedCredentialDetector.RULE_ID, finding.ruleId());
        assertEquals("Hardcoded Credential", finding.vulnerabilityType());
        assertEquals("CWE-798", finding.cwe());
        assertEquals(FindingSeverity.HIGH, finding.severity());
        assertTrue(finding instanceof FindingResult);
    }

    @Test
    void primaryLocationPointsAtLiteralAndIdentifierIsPreserved() {
        PatternFinding finding = only("password", PatternOccurrenceKind.FIELD_DECLARATION);
        assertEquals(4, finding.primaryLocation().startLine());
        assertTrue(finding.primaryLocation().startColumn() > 30);
        assertEquals("password", finding.identifier());
        assertEquals("string_literal", finding.literalKind());
    }

    @Test
    void findingNeverExposesLiteralValue() {
        PatternFinding finding = only("password", PatternOccurrenceKind.FIELD_DECLARATION);
        assertFalse(finding.toString().contains("FieldSecret123!"));
        assertFalse(finding.evidence().contains("FieldSecret123!"));
        assertTrue(finding.evidence().contains("value redacted"));
    }

    @Test
    void oneOccurrenceProducesOnlyOneFinding() {
        PatternFinding field = only("password", PatternOccurrenceKind.FIELD_DECLARATION);
        assertEquals(1, findings.stream()
                .filter(candidate -> candidate.ruleId().equals(field.ruleId()))
                .filter(candidate -> candidate.primaryLocation().equals(field.primaryLocation()))
                .count());
    }

    @Test
    void distinctAssignmentsProduceDistinctFindings() {
        List<PatternFinding> tokenAssignments = matching("token", PatternOccurrenceKind.ASSIGNMENT);
        assertEquals(2, tokenAssignments.size());
        assertEquals(2, tokenAssignments.stream()
                .map(PatternFinding::primaryLocation)
                .collect(Collectors.toSet())
                .size());
    }

    @Test
    void defaultPatternAnalysisKeepsCredentialAndAuthn06AsSeparateDetectors() {
        PatternAnalysis analysis = PatternAnalysis.javaDefaults();
        assertEquals(2, analysis.detectors().size());
        assertTrue(analysis.detectors().getFirst() instanceof HardcodedCredentialDetector);
        assertTrue(analysis.detectors().get(1)
                instanceof Authn06HardcodedSigningMaterialDetector);
        assertNotNull(file);
    }

    private static PatternFinding only(String identifier, PatternOccurrenceKind kind) {
        List<PatternFinding> matches = matching(identifier, kind);
        assertEquals(1, matches.size());
        return matches.getFirst();
    }

    private static List<PatternFinding> matching(String identifier, PatternOccurrenceKind kind) {
        return findings.stream()
                .filter(finding -> finding.identifier().equals(identifier))
                .filter(finding -> finding.occurrenceKind() == kind)
                .toList();
    }

    private static Path fixturePath() throws URISyntaxException {
        var resource = HardcodedCredentialDetectorTest.class
                .getClassLoader()
                .getResource("fixtures/HardcodedCredentialFixture.java");
        if (resource == null) {
            throw new IllegalStateException("STEP 8 fixture not found");
        }
        return Path.of(resource.toURI());
    }
}
