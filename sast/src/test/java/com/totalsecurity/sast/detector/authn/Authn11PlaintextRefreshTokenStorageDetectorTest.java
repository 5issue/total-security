package com.totalsecurity.sast.detector.authn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.finding.ChecklistFlowFinding;
import com.totalsecurity.sast.finding.FindingFlowStepKind;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.java.extractor.JavaSemanticExtractor;
import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import com.totalsecurity.sast.rule.sink.SinkCategory;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class Authn11PlaintextRefreshTokenStorageDetectorTest {
    private static JavaFileInfo file;
    private static ClassInfo service;
    private static JavaFileInfo unsafeFile;
    private static JavaFileInfo persistenceFile;
    private static JavaFileInfo hasherFile;
    private static List<JavaFileInfo> additionalHasherFiles;
    private static List<JavaFileInfo> tryProjectionFiles;
    private static ClassInfo unsafeService;
    private static ClassInfo persistenceService;
    private static ClassInfo reassignedDigestService;
    private static Authn11AnalysisResult result;
    private static Set<String> verifiedHashers;

    @BeforeAll
    static void analyzeFixture() throws Exception {
        try (JavaSourceParser parser = new JavaSourceParser()) {
            try (ParsedJavaFile parsed = parser.parse(fixturePath(
                    "fixtures/authn11/Authn11RefreshTokenStorageFixture.java"))) {
                assertFalse(parsed.hasSyntaxErrors());
                file = new JavaSemanticExtractor().extract(parsed);
            }
            try (ParsedJavaFile parsed = parser.parse(fixturePath(
                    "fixtures/authn11/unsafe/UnverifiedRefreshTokenHasherFixture.java"))) {
                assertFalse(parsed.hasSyntaxErrors());
                unsafeFile = new JavaSemanticExtractor().extract(parsed);
            }
            try (ParsedJavaFile parsed = parser.parse(fixturePath(
                    "fixtures/authn11/Authn11PersistenceProofFixture.java"))) {
                assertFalse(parsed.hasSyntaxErrors());
                persistenceFile = new JavaSemanticExtractor().extract(parsed);
            }
            try (ParsedJavaFile parsed = parser.parse(fixturePath(
                    "fixtures/authn11/Authn11HasherReassignmentFixture.java"))) {
                assertFalse(parsed.hasSyntaxErrors());
                hasherFile = new JavaSemanticExtractor().extract(parsed);
            }
            additionalHasherFiles = new java.util.ArrayList<>();
            for (String fixture : List.of(
                    "fixtures/authn11/ReassignedAlgorithmHasherFixture.java",
                    "fixtures/authn11/AmbiguousAlgorithmHasherFixture.java",
                    "fixtures/authn11/ExactLocalAlgorithmHasherFixture.java")) {
                try (ParsedJavaFile parsed = parser.parse(fixturePath(fixture))) {
                    assertFalse(parsed.hasSyntaxErrors());
                    additionalHasherFiles.add(new JavaSemanticExtractor().extract(parsed));
                }
            }
            tryProjectionFiles = new java.util.ArrayList<>();
            for (String fixture : List.of(
                    "fixtures/authn11/tryprojection/ifmutation/IfMutationHasherFixture.java",
                    "fixtures/authn11/tryprojection/loopmutation/LoopMutationHasherFixture.java",
                    "fixtures/authn11/tryprojection/standalonecall/StandaloneCallHasherFixture.java",
                    "fixtures/authn11/tryprojection/initializercall/InitializerCallHasherFixture.java",
                    "fixtures/authn11/tryprojection/catchsideeffect/CatchSideEffectHasherFixture.java",
                    "fixtures/authn11/tryprojection/customgetbytes/CustomGetBytesHasherFixture.java",
                    "fixtures/authn11/tryprojection/sideeffectgetbytes/SideEffectGetBytesHasherFixture.java")) {
                try (ParsedJavaFile parsed = parser.parse(fixturePath(fixture))) {
                    assertFalse(parsed.hasSyntaxErrors());
                    tryProjectionFiles.add(new JavaSemanticExtractor().extract(parsed));
                }
            }
        }
        service = file.types().stream()
                .filter(type -> type.name().equals("RefreshTokenStorageService"))
                .findFirst().orElseThrow();
        unsafeService = unsafeFile.types().stream()
                .filter(type -> type.name().equals("UnsafeHasherService"))
                .findFirst().orElseThrow();
        persistenceService = persistenceFile.types().stream()
                .filter(type -> type.name().equals("PersistenceProofService"))
                .findFirst().orElseThrow();
        reassignedDigestService = hasherFile.types().stream()
                .filter(type -> type.name().equals("ReassignedDigestStorageService"))
                .findFirst().orElseThrow();
        List<JavaFileInfo> files = new java.util.ArrayList<>(
                List.of(file, unsafeFile, persistenceFile, hasherFile));
        files.addAll(additionalHasherFiles);
        files.addAll(tryProjectionFiles);
        result = new Authn11PlaintextRefreshTokenStorageDetector()
                .analyze(files);
        verifiedHashers = new CryptographicRefreshTokenHasherDiscovery().discover(files);
    }

    @Test
    void detectsDirectAliasAndAssignmentRawPersistence() {
        assertFinding("directRaw");
        assertFinding("localAlias");
        assertFinding("assignedRaw");
    }

    @Test
    void detectsSupportedSameAndCrossClassRawReturnFlows() {
        ChecklistFlowFinding same = assertFinding("sameClassRaw");
        ChecklistFlowFinding cross = assertFinding("crossClassRaw");
        assertTrue(same.flows().stream().flatMap(flow -> flow.steps().stream())
                .anyMatch(step -> step.summary().contains("identityRefreshToken")));
        assertTrue(cross.flows().stream().flatMap(flow -> flow.steps().stream())
                .anyMatch(step -> step.summary().contains("forward")));
    }

    @Test
    void supportedHashOutputPersistenceIsNotReported() {
        assertNoFinding("hashedBeforePersistence");
        assertNoFinding("hashedName");
        assertNoFinding("backendStyleHashed");
    }

    @Test
    void unverifiedMethodNamedHashIsNotTreatedAsCryptographicSanitizer() {
        assertEquals(1, findings(unsafeService, "unverifiedHash").size());
    }

    @Test
    void hashVerificationUsesTheDefinitionReachingEachUse() {
        assertEquals(1, findings(reassignedDigestService, "store").size(),
                () -> "unsupported=" + result.unsupported()
                        + " verified=" + verifiedHashers);
        assertFalse(verifiedHashers.contains(
                "fixtures.authn11.hasher.reassigneddigest.RefreshTokenHasher"));
        assertFalse(verifiedHashers.contains(
                "fixtures.authn11.hasher.reassignedalgorithm.RefreshTokenHasher"));
        assertFalse(verifiedHashers.contains(
                "fixtures.authn11.hasher.ambiguousalgorithm.RefreshTokenHasher"));
        assertTrue(verifiedHashers.contains(
                "fixtures.authn11.hasher.exactlocalalgorithm.RefreshTokenHasher"));
        assertTrue(verifiedHashers.contains("fixtures.authn11.RefreshTokenHasher"));
    }

    @Test
    void tryProjectionRejectsIfMutationAndDoesNotProduceAFalseSanitizer() {
        assertUnverifiedTryHasher("fixtures.authn11.tryprojection.ifmutation");
        ClassInfo mutationService = tryProjectionFiles.getFirst().types().stream()
                .filter(type -> type.name().equals("IfMutationStorageService"))
                .findFirst().orElseThrow();
        MethodInfo store = mutationService.methods().stream()
                .filter(method -> method.name().equals("store"))
                .findFirst().orElseThrow();
        boolean finding = !findings(mutationService, "store").isEmpty();
        boolean unsupported = result.unsupported().stream()
                .anyMatch(item -> item.location().file().equals(store.location().file())
                        && item.location().startLine() >= store.location().startLine()
                        && item.location().endLine() <= store.location().endLine());
        assertTrue(finding || unsupported,
                () -> "unsafe try projection was silently treated as safe: " + result);
    }

    @Test
    void tryProjectionRejectsLoopMutation() {
        assertUnverifiedTryHasher("fixtures.authn11.tryprojection.loopmutation");
    }

    @Test
    void tryProjectionRejectsStandaloneSideEffectCall() {
        assertUnverifiedTryHasher("fixtures.authn11.tryprojection.standalonecall");
    }

    @Test
    void tryProjectionRejectsSideEffectInitializer() {
        assertUnverifiedTryHasher("fixtures.authn11.tryprojection.initializercall");
    }

    @Test
    void tryProjectionRejectsSideEffectingCatch() {
        assertUnverifiedTryHasher("fixtures.authn11.tryprojection.catchsideeffect");
    }

    @Test
    void tryProjectionRejectsCustomGetBytesReceiver() {
        assertUnverifiedTryHasher("fixtures.authn11.tryprojection.customgetbytes");
    }

    @Test
    void tryProjectionRejectsSideEffectingCustomGetBytesReceiver() {
        assertUnverifiedTryHasher("fixtures.authn11.tryprojection.sideeffectgetbytes");
    }

    @Test
    void constructorPayloadRequiresAnExactFinalFieldAssignment() {
        assertEquals(1, findings(persistenceService, "assignedConstructor").size());
        for (String method : List.of(
                "discardedConstructor", "overwrittenConstructor", "unassignedConstructor")) {
            assertTrue(findings(persistenceService, method).isEmpty(), method);
            assertUnsupported(persistenceService, method);
        }
    }

    @Test
    void manualBuilderThatDiscardsItsArgumentIsUnsupported() {
        assertTrue(findings(persistenceService, "fakeBuilder").isEmpty());
        assertUnsupported(persistenceService, "fakeBuilder");
    }

    @Test
    void onlySourceProvenPersistentFieldsParticipateInPayloadMapping() {
        for (String method : List.of(
                "staticField", "jpaTransientField", "javaTransientField")) {
            assertTrue(findings(persistenceService, method).isEmpty(), method);
            assertUnsupported(persistenceService, method);
        }
        assertEquals(1, findings(persistenceService, "customTransientField").size());
    }

    @Test
    void computingHashDoesNotSanitizeSeparateRawPath() {
        assertFinding("hashComputedButRawStored");
    }

    @Test
    void base64EncodingIsNotTreatedAsHashing() {
        assertFinding("base64Only");
    }

    @Test
    void accessAndArbitraryTokensAreNotRefreshTokenSources() {
        assertNoFinding("accessTokenPersistence");
        assertNoFinding("arbitraryTokenPersistence");
    }

    @Test
    void refreshTokenWithoutPersistenceIsNotReported() {
        assertNoFinding("noPersistence");
        assertNoFinding("responseOnly");
    }

    @Test
    void mixedHashedAndRawEntityFieldsRemainFinding() {
        assertFinding("mixedRawAndHash");
    }

    @Test
    void backendDerivedIssueAccessorHashAndBuilderShapeIsDistinguished() {
        assertNoFinding("backendStyleHashed");
        ChecklistFlowFinding raw = assertFinding("backendStyleRaw");
        assertTrue(raw.sources().stream()
                .anyMatch(source -> source.summary().equals("Refresh-token issuance result")));
    }

    @Test
    void findingPreservesChecklistFlowAndExplicitCweAbsence() {
        ChecklistFlowFinding finding = assertFinding("directRaw");
        assertEquals(Authn11PlaintextRefreshTokenStorageDetector.RULE_ID, finding.ruleId());
        assertEquals("AUTHN-11", finding.checklistId());
        assertTrue(finding.cweReference().isEmpty());
        assertEquals("", finding.cwe());
        assertEquals(SinkCategory.REFRESH_TOKEN_PERSISTENCE, finding.sink().category());
        assertTrue(finding.flows().stream().flatMap(flow -> flow.steps().stream())
                .anyMatch(step -> step.kind() == FindingFlowStepKind.SOURCE));
        assertTrue(finding.flows().stream().flatMap(flow -> flow.steps().stream())
                .anyMatch(step -> step.kind() == FindingFlowStepKind.SINK));
    }

    @Test
    void evidenceAndStringFormNeverContainRuntimeTokenValues() {
        ChecklistFlowFinding finding = assertFinding("backendStyleRaw");
        for (String forbidden : Set.of("runtime-token", "SHA-256")) {
            assertFalse(finding.evidence().contains(forbidden));
            assertFalse(finding.toString().contains(forbidden));
        }
        assertTrue(finding.evidence().contains("token value redacted"));
    }

    private static ChecklistFlowFinding assertFinding(String methodName) {
        List<ChecklistFlowFinding> matches = findings(methodName);
        assertEquals(1, matches.size(), methodName);
        return matches.getFirst();
    }

    private static void assertNoFinding(String methodName) {
        assertTrue(findings(methodName).isEmpty(), methodName);
    }

    private static List<ChecklistFlowFinding> findings(String methodName) {
        return findings(service, methodName);
    }

    private static List<ChecklistFlowFinding> findings(
            ClassInfo owner, String methodName) {
        MethodInfo method = owner.methods().stream()
                .filter(candidate -> candidate.name().equals(methodName))
                .findFirst().orElseThrow();
        return result.findings().stream()
                .filter(finding -> finding.primaryLocation().file().equals(method.location().file()))
                .filter(finding -> finding.primaryLocation().startLine() >= method.location().startLine())
                .filter(finding -> finding.primaryLocation().endLine() <= method.location().endLine())
                .toList();
    }

    private static void assertUnsupported(ClassInfo owner, String methodName) {
        MethodInfo method = owner.methods().stream()
                .filter(candidate -> candidate.name().equals(methodName))
                .findFirst().orElseThrow();
        assertTrue(result.unsupported().stream()
                .anyMatch(item -> item.location().file().equals(method.location().file())
                        && item.location().startLine() >= method.location().startLine()
                        && item.location().endLine() <= method.location().endLine()), methodName);
    }

    private static void assertUnverifiedTryHasher(String packageName) {
        assertFalse(verifiedHashers.contains(packageName + ".RefreshTokenHasher"), packageName);
    }

    private static Path fixturePath(String name) throws URISyntaxException {
        var resource = Authn11PlaintextRefreshTokenStorageDetectorTest.class.getClassLoader()
                .getResource(name);
        if (resource == null) {
            throw new IllegalStateException("AUTHN-11 fixture not found");
        }
        return Path.of(resource.toURI());
    }
}
