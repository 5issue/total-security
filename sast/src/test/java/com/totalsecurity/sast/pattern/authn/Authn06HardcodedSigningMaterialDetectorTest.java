package com.totalsecurity.sast.pattern.authn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.finding.PatternFinding;
import com.totalsecurity.sast.finding.PatternOccurrenceKind;
import com.totalsecurity.sast.java.extractor.JavaSemanticExtractor;
import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import com.totalsecurity.sast.pattern.PatternAnalysis;
import com.totalsecurity.sast.pattern.credential.HardcodedCredentialDetector;
import com.totalsecurity.sast.runner.ProjectScanResult;
import com.totalsecurity.sast.runner.ProjectScanner;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class Authn06HardcodedSigningMaterialDetectorTest {
    private static List<PatternFinding> allPatterns;
    private static List<PatternFinding> findings;

    @BeforeAll
    static void analyzeFixture() throws Exception {
        try (JavaSourceParser parser = new JavaSourceParser();
                ParsedJavaFile parsed = parser.parse(fixturePath())) {
            assertFalse(parsed.hasSyntaxErrors());
            allPatterns = PatternAnalysis.javaDefaults()
                    .analyze(new JavaSemanticExtractor().extract(parsed));
        }
        findings = allPatterns.stream()
                .filter(finding -> finding.ruleId().equals(
                        Authn06HardcodedSigningMaterialDetector.RULE_ID))
                .toList();
    }

    @Test
    void detectsJwtAndSigningSecretLiteralsConservatively() {
        assertDetected("JWT_SECRET", PatternOccurrenceKind.FIELD_DECLARATION);
        assertDetected("signingSecret", PatternOccurrenceKind.FIELD_DECLARATION);
        assertDetected("secretKey", PatternOccurrenceKind.FIELD_DECLARATION);
        assertDetected("signingKey", PatternOccurrenceKind.LOCAL_DECLARATION);
        assertDetected("jwtSecret", PatternOccurrenceKind.ASSIGNMENT);
        assertDetected("jwtSecretWithExampleSubstring", PatternOccurrenceKind.FIELD_DECLARATION);
        assertDetected("jwtSecretWithDummySubstring", PatternOccurrenceKind.FIELD_DECLARATION);
    }

    @Test
    void detectsPkcs8RsaAndEcPrivateKeyPemLiterals() {
        assertPrivatePem("privateKey");
        assertPrivatePem("rsaPrivateKey");
        assertPrivatePem("ecPrivateKey");
    }

    @Test
    void publicKeyAndCertificateAreNotPrivateKeyFindings() {
        assertNotDetected("publicKey");
        assertNotDetected("certificate");
    }

    @Test
    void incompleteMismatchedAndReverseOrderedPemMarkersDoNotFallBackToSigningSecret() {
        assertNotDetected("jwtSecretIncompleteBegin");
        assertNotDetected("jwtSecretIncompleteEnd");
        assertNotDetected("jwtSigningSecretIncomplete");
        assertNotDetected("jwtSecretMismatchedPem");
        assertNotDetected("jwtPrivateKeyReverseOrder");
        assertNotDetected("jwtSigningSecretReverseOrder");
        assertNotDetected("rsaPrivateKeyReverseOrder");
    }

    @Test
    void runtimeExternalSourcesAreNotHardcodedSigningMaterial() {
        assertNotDetected("injectedSecret");
        assertNotDetected("jwtSecretFromEnvironment");
        assertNotDetected("signingSecretFromProperty");
        assertNotDetected("signingKeyFromKms");
    }

    @Test
    void messagesMetadataPlaceholdersAndEmptyStringsAreNotFindings() {
        Set<String> identifiers = Set.of(
                "message",
                "signingAlgorithm",
                "signingKeyAlias",
                "jwtSecretPlaceholder",
                "jwtSecretChangeMe",
                "jwtSecretProperty",
                "jwtSecretEmpty",
                "examplePrivateKey");
        identifiers.forEach(Authn06HardcodedSigningMaterialDetectorTest::assertNotDetected);
    }

    @Test
    void metadataIdentifiesChecklistWithoutInventingCweAndRedactsValues() {
        PatternFinding finding = only("JWT_SECRET");
        assertEquals(Authn06HardcodedSigningMaterialDetector.RULE_ID, finding.ruleId());
        assertEquals(Authn06HardcodedSigningMaterialDetector.VULNERABILITY_TYPE,
                finding.vulnerabilityType());
        assertTrue(finding.cweReference().isEmpty());
        assertEquals("", finding.cwe());
        assertTrue(finding.evidence().contains("AUTHN-06"));
        assertTrue(finding.evidence().contains("JWT_SECRET"));
        assertTrue(finding.evidence().contains("value redacted"));
        assertFalse(finding.evidence().contains("a-real-looking-signing-secret-value"));
        assertFalse(finding.toString().contains("a-real-looking-signing-secret-value"));
    }

    @Test
    void privateKeyPemBodyIsNeverExposed() {
        PatternFinding finding = only("privateKey");
        assertFalse(finding.evidence().contains("base64-private-material"));
        assertFalse(finding.toString().contains("base64-private-material"));
    }

    @Test
    void distinctVulnerableLocationsProduceDistinctFindings() {
        List<PatternFinding> distinct = findings.stream()
                .filter(finding -> Set.of("jwtSecretOne", "jwtSecretTwo")
                        .contains(finding.identifier()))
                .toList();
        assertEquals(2, distinct.size());
        assertEquals(2, distinct.stream()
                .map(PatternFinding::primaryLocation)
                .collect(Collectors.toSet())
                .size());
    }

    @Test
    void specificChecklistAndExistingCwe798RemainSeparateRules() {
        PatternFinding authn = only("secretKey");
        List<PatternFinding> credential = allPatterns.stream()
                .filter(finding -> finding.identifier().equals("secretKey"))
                .filter(finding -> finding.ruleId().equals(HardcodedCredentialDetector.RULE_ID))
                .toList();
        assertEquals(1, credential.size());
        assertEquals("CWE-798", credential.getFirst().cwe());
        assertEquals("", authn.cwe());
        assertFalse(authn.ruleId().equals(credential.getFirst().ruleId()));
    }

    @Test
    void productionScannerDoesNotDependOnFixturePathOrPackage(@TempDir Path temporary)
            throws Exception {
        for (String projectName : List.of("first-project", "renamed-project")) {
            Path project = temporary.resolve(projectName);
            Path source = project.resolve("module/src/main/java/arbitrary/location/Unexpected.java");
            Files.createDirectories(source.getParent());
            Files.writeString(
                    source,
                    """
                    package arbitrary.location;
                    class Unexpected {
                        String jwtSecret = "path-independent-signing-material";
                    }
                    """,
                    StandardCharsets.UTF_8);

            ProjectScanResult scan = ProjectScanner.javaDefaults().scan(project);
            assertEquals(1, scan.findings().stream()
                    .filter(finding -> finding.ruleId().equals(
                            Authn06HardcodedSigningMaterialDetector.RULE_ID))
                    .count());
        }
    }

    private static void assertPrivatePem(String identifier) {
        PatternFinding finding = only(identifier);
        assertTrue(finding.evidence().contains("private-key PEM literal"));
    }

    private static void assertDetected(String identifier, PatternOccurrenceKind occurrence) {
        assertEquals(occurrence, only(identifier).occurrenceKind());
    }

    private static void assertNotDetected(String identifier) {
        assertTrue(findings.stream().noneMatch(finding -> finding.identifier().equals(identifier)));
    }

    private static PatternFinding only(String identifier) {
        List<PatternFinding> matches = findings.stream()
                .filter(finding -> finding.identifier().equals(identifier))
                .toList();
        assertEquals(1, matches.size(), identifier);
        return matches.getFirst();
    }

    private static Path fixturePath() throws URISyntaxException {
        var resource = Authn06HardcodedSigningMaterialDetectorTest.class
                .getClassLoader()
                .getResource("fixtures/Authn06HardcodedSigningMaterialFixture.java");
        if (resource == null) {
            throw new IllegalStateException("AUTHN-06 fixture not found");
        }
        return Path.of(resource.toURI());
    }
}
