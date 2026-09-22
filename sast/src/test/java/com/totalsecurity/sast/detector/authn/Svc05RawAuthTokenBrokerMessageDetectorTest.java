package com.totalsecurity.sast.detector.authn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.finding.ChecklistFlowFinding;
import com.totalsecurity.sast.finding.FindingFlowStepKind;
import com.totalsecurity.sast.interprocedural.ProjectClassIndex;
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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class Svc05RawAuthTokenBrokerMessageDetectorTest {
    private static JavaFileInfo fixture;
    private static JavaFileInfo backendDerived;
    private static ClassInfo publisher;
    private static Svc05AnalysisResult result;

    @BeforeAll
    static void analyzeFixture() throws Exception {
        try (JavaSourceParser parser = new JavaSourceParser()) {
            try (ParsedJavaFile parsed = parser.parse(fixturePath(
                    "fixtures/svc05/Svc05BrokerMessageFixture.java"))) {
                assertFalse(parsed.hasSyntaxErrors());
                fixture = new JavaSemanticExtractor().extract(parsed);
            }
            try (ParsedJavaFile parsed = parser.parse(fixturePath(
                    "fixtures/svc05/Svc05BackendDerivedRabbitFixture.java"))) {
                assertFalse(parsed.hasSyntaxErrors());
                backendDerived = new JavaSemanticExtractor().extract(parsed);
            }
        }
        publisher = fixture.types().stream()
                .filter(type -> type.name().equals("Svc05BrokerMessageFixture"))
                .findFirst().orElseThrow();
        result = new Svc05RawAuthTokenBrokerMessageDetector()
                .analyze(List.of(fixture, backendDerived));
    }

    @Test
    void detectsDirectAccessAndRefreshTokenPayloads() {
        assertFinding("directAccess");
        assertFinding("directRefresh");
        assertFinding("directBearer");
        assertFinding("directAuthorization");
        assertFinding("directJwt");
    }

    @Test
    void preservesAliasAndAssignmentFlows() {
        assertFinding("alias");
        assertFinding("assignment");
    }

    @Test
    void reversibleBase64EncodingRemainsRaw() {
        assertFinding("base64");
    }

    @Test
    void mapsExactConstructorAndRecordPayloads() {
        assertFinding("dtoConstructor");
        assertFinding("recordPayload");
        assertFinding("mixedPayload");
    }

    @Test
    void mapsExactLombokBuilderAndJsonSerialization() {
        assertFinding("lombokBuilder");
        assertFinding("jsonSerialization");
    }

    @Test
    void supportsSameAndCrossClassReturnSummaries() {
        ChecklistFlowFinding same = assertFinding("sameClassHelper");
        ChecklistFlowFinding cross = assertFinding("crossClassHelper");
        for (ChecklistFlowFinding finding : List.of(same, cross)) {
            assertTrue(finding.flows().stream().flatMap(flow -> flow.steps().stream())
                    .anyMatch(step -> step.kind() == FindingFlowStepKind.METHOD_CALL));
            assertTrue(finding.flows().stream().flatMap(flow -> flow.steps().stream())
                    .anyMatch(step -> step.kind() == FindingFlowStepKind.PARAMETER_BINDING));
            assertTrue(finding.flows().stream().flatMap(flow -> flow.steps().stream())
                    .anyMatch(step -> step.kind() == FindingFlowStepKind.METHOD_RETURN));
        }
    }

    @Test
    void exactIssuerRecordTokenAndAuthorizationHeaderAreSources() {
        assertFinding("issuedToken");
        assertFinding("authorizationHeader");
    }

    @Test
    void identifierOnlyAndUnpublishedTokenAreNotFindings() {
        assertNoFinding("identifierOnly");
        assertNoFinding("accessTokenNotPublished");
        assertNoFinding(backendDerived.types().stream()
                .filter(type -> type.name().equals("BackendDerivedOrderPublisher"))
                .findFirst().orElseThrow(), "publishOrder");
    }

    @Test
    void devicePushAndVerificationTokensAreExcludedSources() {
        assertNoFinding("excludedTokens");
        assertNoFinding("metadataIdentifiers");
    }

    @Test
    void sendNamesAndInProcessEventsAreNotBrokerSinks() {
        assertNoFinding("nonBrokerSend");
        assertNoFinding("inProcessEvent");
    }

    @Test
    void resolvesSignatureProvenRabbitTemplatePayloadIndexes() {
        assertEquals(1, assertFinding("routingKeyCallbackOverload").sink().argumentIndex());
        assertEquals(1, assertFinding("routingKeyCorrelationOverload").sink().argumentIndex());
        assertEquals(2, assertFinding("directAccess").sink().argumentIndex());
        assertEquals(2, assertFinding("exchangePostProcessorOverload").sink().argumentIndex());
        assertEquals(2, assertFinding("exchangeCorrelationOverload").sink().argumentIndex());
    }

    @Test
    void ambiguousLambdaRabbitOverloadIsUnsupported() {
        assertNoFinding("ambiguousLambdaOverload");
        assertUnsupported("ambiguousLambdaOverload");
    }

    @Test
    void unsupportedManualBuilderAndIncompleteConstructorsAreNotFindings() {
        for (String method : List.of(
                "manualBuilderDiscard", "constructorDiscard", "constructorOverwrite")) {
            assertNoFinding(method);
            assertUnsupported(method);
        }
    }

    @Test
    void exactHashRemovesRawMeaningButNameOnlyHashDoesNot() {
        assertNoFinding("exactHashRemovesRawMeaning");
        assertFinding("nameOnlyHashDoesNotRemoveRawMeaning");
    }

    @Test
    void issuerMetadataAccessorIsNotRawTokenSource() {
        assertNoFinding("issuerMetadataIsNotToken");
        assertNoFinding("manuallyConstructedIssuerRecordIsNotSource");
    }

    @Test
    void multipleTokenSourcesMergeAtOnePhysicalSink() {
        ChecklistFlowFinding finding = assertFinding("multipleTokens");
        assertEquals(2, finding.sources().size());
        assertEquals(2, finding.flows().size());
    }

    @Test
    void findingPreservesChecklistIdentitySinkAndExplicitCweAbsence() {
        ChecklistFlowFinding finding = assertFinding("directAccess");
        assertEquals(Svc05RawAuthTokenBrokerMessageDetector.RULE_ID, finding.ruleId());
        assertEquals("SVC-05", finding.checklistId());
        assertTrue(finding.cweReference().isEmpty());
        assertEquals("", finding.cwe());
        assertEquals(SinkCategory.ASYNC_MESSAGE_PUBLISH, finding.sink().category());
        assertEquals(2, finding.sink().argumentIndex());
    }

    @Test
    void evidenceAndProvenanceRedactTokenValues() {
        ChecklistFlowFinding finding = assertFinding("redactedEvidence");
        String rendered = finding.toString();
        assertFalse(rendered.contains("eyJhbGciOiJIUzI1NiJ9"));
        assertFalse(finding.evidence().contains("eyJhbGciOiJIUzI1NiJ9"));
        assertTrue(finding.evidence().contains("token value redacted"));
    }

    @Test
    void exactRabbitTemplateSinkDoesNotDependOnFixtureOrBackendFqn() {
        ProjectClassIndex index = new ProjectClassIndex(List.of(fixture, backendDerived));
        assertTrue(index.uniqueClass("fixtures.svc05.Svc05BrokerMessageFixture").isPresent());
        assertFinding("directAccess");
        assertNoFinding("nonBrokerSend");
    }

    private static ChecklistFlowFinding assertFinding(String methodName) {
        List<ChecklistFlowFinding> matches = findings(publisher, methodName);
        assertEquals(1, matches.size(), methodName + ": " + result.unsupported());
        return matches.getFirst();
    }

    private static void assertNoFinding(String methodName) {
        assertNoFinding(publisher, methodName);
    }

    private static void assertNoFinding(ClassInfo owner, String methodName) {
        assertTrue(findings(owner, methodName).isEmpty(), methodName);
    }

    private static List<ChecklistFlowFinding> findings(ClassInfo owner, String methodName) {
        MethodInfo method = method(owner, methodName);
        return result.findings().stream()
                .filter(finding -> finding.primaryLocation().file().equals(method.location().file()))
                .filter(finding -> finding.primaryLocation().startLine() >= method.location().startLine())
                .filter(finding -> finding.primaryLocation().endLine() <= method.location().endLine())
                .toList();
    }

    private static void assertUnsupported(String methodName) {
        MethodInfo method = method(publisher, methodName);
        assertTrue(result.unsupported().stream()
                .anyMatch(item -> item.location().file().equals(method.location().file())
                        && item.location().startLine() >= method.location().startLine()
                        && item.location().endLine() <= method.location().endLine()), methodName);
    }

    private static MethodInfo method(ClassInfo owner, String methodName) {
        return owner.methods().stream()
                .filter(candidate -> candidate.name().equals(methodName))
                .findFirst().orElseThrow();
    }

    private static Path fixturePath(String name) throws URISyntaxException {
        var resource = Svc05RawAuthTokenBrokerMessageDetectorTest.class
                .getClassLoader().getResource(name);
        if (resource == null) {
            throw new IllegalStateException("SVC-05 fixture not found: " + name);
        }
        return Path.of(resource.toURI());
    }
}
