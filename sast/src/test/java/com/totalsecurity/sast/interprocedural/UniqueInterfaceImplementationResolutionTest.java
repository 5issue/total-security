package com.totalsecurity.sast.interprocedural;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.detector.sql.SqlInjectionDetector;
import com.totalsecurity.sast.finding.Finding;
import com.totalsecurity.sast.finding.FindingFlowStepKind;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.java.extractor.JavaSemanticExtractor;
import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import com.totalsecurity.sast.rule.RuleRegistry;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class UniqueInterfaceImplementationResolutionTest {
    private static final String PACKAGE = "fixtures.interfaceimpl.";
    private static CrossClassInterproceduralResult result;

    @BeforeAll
    static void analyzeFixtures() throws Exception {
        List<JavaFileInfo> files = new ArrayList<>();
        try (JavaSourceParser parser = new JavaSourceParser()) {
            for (String resource : resources()) {
                try (ParsedJavaFile parsed = parser.parse(fixturePath(resource))) {
                    assertFalse(parsed.hasSyntaxErrors(), resource);
                    files.add(new JavaSemanticExtractor().extract(parsed));
                }
            }
        }
        result = new CrossClassInterproceduralAnalysis()
                .analyze(files, RuleRegistry.javaSpringBackendDefaults());
    }

    @Test
    void resolvesUniqueDirectImplementationAndRetainsDispatchDetail() {
        ProjectCallResolution resolution = resolution("DirectCaller", "call", "process");

        assertTarget(resolution, "DirectImplementation", "process");
        InterfaceDispatchInfo dispatch = resolution.interfaceDispatch().orElseThrow();
        assertEquals(PACKAGE + "DirectPort", dispatch.declaredInterface());
        assertEquals(PACKAGE + "DirectImplementation", dispatch.resolvedImplementation());
    }

    @Test
    void interfaceTypeNameReceiverDoesNotDispatchToUniqueImplementation() {
        ProjectCallResolution resolution = resolution(
                "StaticStyleController", "run", "process");

        assertEquals(SameClassCallStatus.UNSUPPORTED, resolution.status());
        assertEquals(UnsupportedInterproceduralReason.INTERFACE_DISPATCH,
                resolution.unsupported().orElseThrow().reason());
        assertTrue(resolution.target().isEmpty());
        assertTrue(resolution.interfaceDispatch().isEmpty());
    }

    @Test
    void interfaceTypeNameReceiverDoesNotCreateFalseSqlFinding() {
        MethodInfo source = method("StaticStyleController", "run");

        assertTrue(result.findings().stream()
                .filter(finding -> finding.ruleId().equals(SqlInjectionDetector.RULE_ID))
                .flatMap(finding -> finding.sources().stream())
                .noneMatch(candidate -> within(source, candidate.location())));
    }

    @Test
    void parameterReceiverRemainsAProvenInstanceValue() {
        assertTarget(
                resolution("ParameterCaller", "call", "process"),
                "DirectImplementation",
                "process");
    }

    @Test
    void unresolvedSameNameReceiverRemainsUnsupported() {
        ProjectCallResolution resolution = resolution(
                "UnresolvedSameNameCaller", "call", "process");

        assertEquals(UnsupportedInterproceduralReason.INTERFACE_DISPATCH,
                resolution.unsupported().orElseThrow().reason());
        assertTrue(resolution.target().isEmpty());
        assertTrue(resolution.interfaceDispatch().isEmpty());
    }

    @Test
    void resolvesUniqueImplementationThroughInterfaceExtension() {
        assertTarget(
                resolution("ParentCaller", "call", "process"),
                "ChildImplementation",
                "process");
    }

    @Test
    void multipleImplementationsRemainInterfaceDispatch() {
        assertUnsupported(
                "MultipleCaller", "call", "process",
                UnsupportedInterproceduralReason.INTERFACE_DISPATCH,
                "Multiple concrete project implementations");
    }

    @Test
    void duplicateImplementationFqnIsNeverSelected() {
        assertUnsupported(
                "DuplicateImplementationCaller", "call", "process",
                UnsupportedInterproceduralReason.INTERFACE_DISPATCH,
                "duplicate FQN");
    }

    @Test
    void abstractCandidateIsExcludedAndConcreteSubclassCanBeProven() {
        ProjectClassEntry abstractBase = type("AbstractBase");
        ProjectClassEntry real = type("RealImplementation");

        assertTrue(abstractBase.type().abstractType());
        assertFalse(real.type().abstractType());
        assertTarget(
                resolution("AbstractCaller", "call", "process"),
                "RealImplementation",
                "process");
    }

    @Test
    void interfaceWithoutImplementationRemainsUnsupported() {
        assertUnsupported(
                "MissingCaller", "call", "process",
                UnsupportedInterproceduralReason.INTERFACE_DISPATCH,
                "No unique analyzable concrete project implementation");
    }

    @Test
    void springStereotypeWithoutHierarchyIsNotDispatchEvidence() {
        assertUnsupported(
                "AnnotationOnlyCaller", "call", "process",
                UnsupportedInterproceduralReason.INTERFACE_DISPATCH,
                "No unique analyzable concrete project implementation");
    }

    @Test
    void springDataRepositoryHierarchyRemainsRuntimeProxyDispatch() {
        assertUnsupported(
                "RuntimeProxyCaller", "call", "findById",
                UnsupportedInterproceduralReason.INTERFACE_DISPATCH,
                "Spring Data repository proxy hierarchy");
    }

    @Test
    void projectRepositoryAdapterResolvesButItsJpaProxyDoesNot() {
        assertTarget(
                resolution("ProjectRepositoryCaller", "call", "search"),
                "ProjectRepositoryImplementation",
                "search");
        assertUnsupported(
                "ProjectRepositoryImplementation", "search", "search",
                UnsupportedInterproceduralReason.INTERFACE_DISPATCH,
                "Spring Data repository proxy hierarchy");
    }

    @Test
    void implementationOverloadUsesExistingExactTypePolicy() {
        ProjectCallResolution resolution = resolution("OverloadCaller", "call", "route");

        assertTarget(resolution, "OverloadImplementation", "route");
        assertEquals("String", resolution.target().orElseThrow()
                .method().parameters().getFirst().type());
    }

    @Test
    void bodylessImplementationMethodIsNotUsedAsSummaryTarget() {
        assertUnsupported(
                "BodylessCaller", "call", "process",
                UnsupportedInterproceduralReason.NO_ANALYZABLE_BODY,
                "has no analyzable method body");
    }

    @Test
    void interfaceDispatchCycleUsesExistingRecursionPolicy() {
        assertUnsupported(
                "CycleCaller", "call", "process",
                UnsupportedInterproceduralReason.RECURSIVE_CALL,
                "Recursive project-local edge");
        assertUnsupported(
                "CycleImplementation", "process", "call",
                UnsupportedInterproceduralReason.RECURSIVE_CALL,
                "Recursive project-local edge");
    }

    @Test
    void duplicateInterfaceFqnRemainsAmbiguous() {
        assertUnsupported(
                "DuplicateInterfaceCaller", "call", "process",
                UnsupportedInterproceduralReason.AMBIGUOUS_CLASS,
                "Duplicate project class FQN");
    }

    @Test
    void directConcreteReceiverRegressionStillResolvesNormally() {
        ProjectCallResolution resolution = resolution("ConcreteCaller", "call", "process");

        assertTarget(resolution, "ConcreteService", "process");
        assertTrue(resolution.interfaceDispatch().isEmpty());
    }

    @Test
    void sourceCrossesTwoUniqueInterfacesAndReachesPhysicalSqlSink() {
        Finding finding = result.findings().stream()
                .filter(candidate -> candidate.ruleId().equals(SqlInjectionDetector.RULE_ID))
                .filter(candidate -> within(method("SearchController", "search"),
                        candidate.sources().getFirst().location()))
                .findFirst().orElseThrow();

        assertTrue(within(method("SearchRepositoryImplementation", "search"),
                finding.sink().location()));
        List<String> dispatchSteps = finding.flows().stream()
                .flatMap(flow -> flow.steps().stream())
                .filter(step -> step.kind() == FindingFlowStepKind.METHOD_CALL)
                .map(step -> step.summary())
                .filter(summary -> summary.contains("declared interface"))
                .toList();
        assertEquals(2, dispatchSteps.size());
        assertTrue(dispatchSteps.stream().anyMatch(summary ->
                summary.contains(PACKAGE + "SearchService")
                        && summary.contains(PACKAGE + "SearchServiceImplementation")));
        assertTrue(dispatchSteps.stream().anyMatch(summary ->
                summary.contains(PACKAGE + "SearchRepository")
                        && summary.contains(PACKAGE + "SearchRepositoryImplementation")));
    }

    @Test
    void ambiguousImplementationDoesNotCreateAFlowFinding() {
        MethodInfo source = method("AmbiguousSearchController", "search");
        assertTrue(result.findings().stream()
                .flatMap(finding -> finding.sources().stream())
                .noneMatch(candidate -> within(source, candidate.location())));
    }

    private static void assertTarget(
            ProjectCallResolution resolution, String owner, String method) {
        assertEquals(PACKAGE + owner, resolution.target().orElseThrow().ownerQualifiedName());
        assertEquals(method, resolution.target().orElseThrow().method().name());
    }

    private static void assertUnsupported(
            String owner,
            String callerMethod,
            String calledMethod,
            UnsupportedInterproceduralReason reason,
            String detail) {
        UnsupportedInterproceduralFlow unsupported = resolution(
                owner, callerMethod, calledMethod).unsupported().orElseThrow();
        assertEquals(reason, unsupported.reason());
        assertTrue(unsupported.detail().contains(detail), unsupported.detail());
    }

    private static ProjectCallResolution resolution(
            String owner, String callerMethod, String calledMethod) {
        ProjectMethodId caller = methodId(owner, callerMethod);
        return result.callResolutions().stream()
                .filter(candidate -> candidate.caller().equals(caller))
                .filter(candidate -> candidate.call().call().methodName().equals(calledMethod))
                .findFirst().orElseThrow();
    }

    private static ProjectMethodId methodId(String owner, String method) {
        return result.methodSummaries().keySet().stream()
                .filter(candidate -> candidate.ownerQualifiedName().equals(PACKAGE + owner))
                .filter(candidate -> candidate.method().name().equals(method))
                .findFirst().orElseThrow();
    }

    private static MethodInfo method(String owner, String method) {
        return methodId(owner, method).method();
    }

    private static ProjectClassEntry type(String simpleName) {
        return result.classIndex().uniqueClass(PACKAGE + simpleName).orElseThrow();
    }

    private static boolean within(MethodInfo method, SourceLocation location) {
        return method.location().file().equals(location.file())
                && location.startLine() >= method.location().startLine()
                && location.startLine() <= method.location().endLine();
    }

    private static List<String> resources() {
        return List.of(
                "fixtures/interfaceimpl/InterfaceImplementationFixture.java",
                "fixtures/interfaceimpl/DuplicatePort.java",
                "fixtures/interfaceimpl/duplicate/one/DuplicateImplementation.java",
                "fixtures/interfaceimpl/duplicate/two/DuplicateImplementation.java",
                "fixtures/interfaceimpl/duplicateport/one/AmbiguousOwnerPort.java",
                "fixtures/interfaceimpl/duplicateport/two/AmbiguousOwnerPort.java");
    }

    private static Path fixturePath(String resource) throws URISyntaxException {
        var value = UniqueInterfaceImplementationResolutionTest.class
                .getClassLoader().getResource(resource);
        if (value == null) {
            throw new IllegalStateException("STEP 24 fixture not found: " + resource);
        }
        return Path.of(value.toURI());
    }
}
