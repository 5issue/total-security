package com.totalsecurity.sast.interprocedural;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.detector.command.CommandInjectionDetector;
import com.totalsecurity.sast.detector.ldap.LdapInjectionDetector;
import com.totalsecurity.sast.detector.path.PathTraversalDetector;
import com.totalsecurity.sast.detector.sql.SqlInjectionDetector;
import com.totalsecurity.sast.detector.ssrf.SsrfDetector;
import com.totalsecurity.sast.finding.Finding;
import com.totalsecurity.sast.finding.FindingFlowStepKind;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.java.extractor.JavaSemanticExtractor;
import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import com.totalsecurity.sast.rule.RuleRegistry;
import com.totalsecurity.sast.rule.sink.SinkCategory;
import com.totalsecurity.sast.taint.TaintState;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class CrossClassInterproceduralAnalysisTest {
    private static final String CONTROLLER = "fixtures.crossclass.controller.UserController";
    private static final String SERVICE = "fixtures.crossclass.service.UserService";
    private static final String SAME_PACKAGE = "fixtures.crossclass.service.SamePackageHelper";
    private static final String REPOSITORY = "fixtures.crossclass.repository.UserRepository";
    private static final String OUTBOUND = "fixtures.crossclass.outbound.OutboundGateway";
    private static final String OVERLOAD = "fixtures.crossclass.external.OverloadService";
    private static final String INT_SERVICE = "fixtures.crossclass.external.IntService";
    private static final String AMBIGUOUS = "fixtures.crossclass.external.AmbiguousService";
    private static final String USER_PORT = "fixtures.crossclass.external.UserPort";
    private static final String BASE = "fixtures.crossclass.external.BaseService";
    private static final String CHILD = "fixtures.crossclass.external.ChildService";
    private static final String CYCLE_A = "fixtures.crossclass.cycle.CycleA";
    private static final String CYCLE_B = "fixtures.crossclass.cycle.CycleB";
    private static final String BODYLESS_CONTROLLER =
            "fixtures.crossclass.bodyless.BodylessController";
    private static final String EXACT_EXTERNAL_CALLER =
            "fixtures.crossclass.exactexternal.ExternalCaller";
    private static CrossClassInterproceduralResult result;

    @BeforeAll
    static void analyzeProjectFixtures() throws Exception {
        List<JavaFileInfo> files = new ArrayList<>();
        try (JavaSourceParser parser = new JavaSourceParser()) {
            for (String resource : fixtureResources()) {
                try (ParsedJavaFile parsed = parser.parse(fixturePath(resource))) {
                    assertFalse(parsed.hasSyntaxErrors(), resource);
                    files.add(new JavaSemanticExtractor().extract(parsed));
                }
            }
        }
        result = new CrossClassInterproceduralAnalysis()
                .analyze(files, RuleRegistry.javaSpringBackendDefaults());
    }

    @ParameterizedTest
    @MethodSource("supportedCategoryFlows")
    void supportedCategoriesCrossProjectClassBoundaries(
            String sourceMethod,
            String sinkOwner,
            String sinkMethod,
            SinkCategory category,
            String ruleId) {
        Finding finding = findingFrom(CONTROLLER, sourceMethod, sinkOwner, sinkMethod, category);
        assertEquals(ruleId, finding.ruleId());
        assertTrue(finding.flows().stream().flatMap(flow -> flow.steps().stream())
                .anyMatch(step -> step.kind() == FindingFlowStepKind.METHOD_CALL));
        assertTrue(finding.flows().stream().flatMap(flow -> flow.steps().stream())
                .anyMatch(step -> step.kind() == FindingFlowStepKind.PARAMETER_BINDING));
    }

    private static Stream<Arguments> supportedCategoryFlows() {
        return Stream.of(
                Arguments.of("sql", REPOSITORY, "sql", SinkCategory.SQL_TEXT,
                        SqlInjectionDetector.RULE_ID),
                Arguments.of("command", REPOSITORY, "command", SinkCategory.COMMAND_EXECUTION,
                        CommandInjectionDetector.RULE_ID),
                Arguments.of("path", REPOSITORY, "path", SinkCategory.FILESYSTEM_PATH,
                        PathTraversalDetector.RULE_ID),
                Arguments.of("ssrf", OUTBOUND, "request", SinkCategory.NETWORK_REQUEST_TARGET,
                        SsrfDetector.RULE_ID),
                Arguments.of("ldap", REPOSITORY, "ldap", SinkCategory.LDAP_FILTER,
                        LdapInjectionDetector.RULE_ID));
    }

    @Test
    void constructorInjectedFieldUsesDeclaredProjectType() {
        assertResolved(CONTROLLER, "sql", SERVICE, "sql");
        findingFrom(CONTROLLER, "sql", REPOSITORY, "sql", SinkCategory.SQL_TEXT);
    }

    @Test
    void fieldInjectedReceiverUsesTypeNotAutowiredAnnotation() {
        assertResolved(CONTROLLER, "ssrf", OUTBOUND, "request");
        findingFrom(CONTROLLER, "ssrf", OUTBOUND, "request",
                SinkCategory.NETWORK_REQUEST_TARGET);
    }

    @Test
    void parameterReceiverTypeResolvesExactly() {
        assertResolved(CONTROLLER, "parameterReceiver", SERVICE, "sql");
        findingFrom(CONTROLLER, "parameterReceiver", REPOSITORY, "sql", SinkCategory.SQL_TEXT);
    }

    @Test
    void localReceiverTypeResolvesExactly() {
        assertResolved(CONTROLLER, "localReceiver", SERVICE, "sql");
        findingFrom(CONTROLLER, "localReceiver", REPOSITORY, "sql", SinkCategory.SQL_TEXT);
    }

    @Test
    void samePackageSimpleTypeResolvesThroughProjectIndex() {
        assertResolved(SERVICE, "mixed", SAME_PACKAGE, "forward");
        findingFrom(CONTROLLER, "mixed", REPOSITORY, "sql", SinkCategory.SQL_TEXT);
    }

    @Test
    void explicitImportedProjectTypeResolves() {
        assertResolved(CONTROLLER, "sql", SERVICE, "sql");
    }

    @Test
    void mixedSameAndCrossClassChainPreservesEveryCallBoundary() {
        Finding finding = findingFrom(CONTROLLER, "mixed", REPOSITORY, "sql", SinkCategory.SQL_TEXT);
        List<String> calls = flowFrom(CONTROLLER, "mixed", finding).stream()
                .filter(step -> step.kind() == FindingFlowStepKind.METHOD_CALL)
                .map(step -> step.summary())
                .toList();
        assertEquals(List.of(
                "Project call " + CONTROLLER + "#mixed -> " + CONTROLLER + "#privateHelper",
                "Project call " + CONTROLLER + "#privateHelper -> " + SERVICE + "#mixed",
                "Project call " + SERVICE + "#mixed -> " + SAME_PACKAGE + "#forward",
                "Project call " + SAME_PACKAGE + "#forward -> " + REPOSITORY + "#sql"), calls);
    }

    @Test
    void threeClassPropagationMapsEachArgumentToParameter() {
        Finding finding = findingFrom(CONTROLLER, "sql", REPOSITORY, "sql", SinkCategory.SQL_TEXT);
        long bindings = flowFrom(CONTROLLER, "sql", finding).stream()
                .filter(step -> step.kind() == FindingFlowStepKind.PARAMETER_BINDING)
                .count();
        assertEquals(3, bindings);
    }

    @Test
    void crossClassReturnFeedsCallerSinkWithNestedReturnProvenance() {
        Finding finding = findingFrom(
                CONTROLLER, "returned", CONTROLLER, "returned", SinkCategory.SQL_TEXT);
        List<String> boundaries = flowFrom(CONTROLLER, "returned", finding).stream()
                .filter(step -> step.kind() == FindingFlowStepKind.METHOD_CALL
                        || step.kind() == FindingFlowStepKind.PARAMETER_BINDING
                        || step.kind() == FindingFlowStepKind.METHOD_RETURN)
                .map(step -> step.summary())
                .toList();
        assertEquals(List.of(
                "Project call " + CONTROLLER + "#returned -> " + SERVICE + "#buildSql",
                "Bind argument 0 to " + SERVICE + "#buildSql parameter value",
                "Project call " + SERVICE + "#buildSql -> " + REPOSITORY + "#decorate",
                "Bind argument 0 to " + REPOSITORY + "#decorate parameter value",
                "Return from " + REPOSITORY + "#decorate",
                "Return from " + SERVICE + "#buildSql"), boundaries);
    }

    @Test
    void uniqueCrossClassOverloadUsesExactStringType() {
        ProjectCallResolution resolution = resolution(CONTROLLER, "overload", "route");
        assertEquals(OVERLOAD, resolution.target().orElseThrow().ownerQualifiedName());
        assertEquals("String", resolution.target().orElseThrow()
                .method().parameters().getFirst().type());
        findingFrom(CONTROLLER, "overload", REPOSITORY, "sql", SinkCategory.SQL_TEXT);
    }

    @Test
    void actualControllerSourceAndRepositorySinkLocationsArePreserved() {
        Finding finding = findingFrom(CONTROLLER, "sql", REPOSITORY, "sql", SinkCategory.SQL_TEXT);
        assertTrue(finding.sources().stream()
                .anyMatch(source -> within(method(CONTROLLER, "sql"), source.location())));
        assertTrue(within(method(REPOSITORY, "sql"), finding.sink().location()));
    }

    @Test
    void multipleOriginsMergeAtOnePhysicalRepositorySink() {
        Finding finding = findingFrom(
                CONTROLLER, "multipleOrigins", REPOSITORY, "sql", SinkCategory.SQL_TEXT);
        assertEquals(1, result.findings().stream()
                .filter(candidate -> candidate.ruleId().equals(SqlInjectionDetector.RULE_ID))
                .filter(candidate -> candidate.sink().location().equals(finding.sink().location()))
                .count());
        assertTrue(finding.sources().stream().anyMatch(source -> source.summary().contains("left")));
        assertTrue(finding.sources().stream().anyMatch(source -> source.summary().contains("right")));
    }

    @Test
    void cleanValueDoesNotReachProjectSinkAsTainted() {
        assertNoSourceFrom(CONTROLLER, "clean");
    }

    @Test
    void overwrittenControllerSourceDoesNotReachProjectSink() {
        assertNoSourceFrom(CONTROLLER, "overwritten");
    }

    @ParameterizedTest
    @MethodSource("unresolvedReceiverCases")
    void unresolvedOrExternalReceiverIsNotGuessedAsProjectClass(
            String methodName, UnsupportedInterproceduralReason reason) {
        assertUnsupported(CONTROLLER, methodName, reason);
        assertNoSourceFrom(CONTROLLER, methodName);
    }

    private static Stream<Arguments> unresolvedReceiverCases() {
        return Stream.of(
                Arguments.of("objectReceiver", UnsupportedInterproceduralReason.EXTERNAL_CLASS),
                Arguments.of("externalReceiver", UnsupportedInterproceduralReason.EXTERNAL_CLASS),
                Arguments.of("customAnnotationOnly", UnsupportedInterproceduralReason.EXTERNAL_CLASS));
    }

    @Test
    void duplicateSimpleNamesWithoutUniqueImportAreAmbiguous() {
        assertUnsupported(
                "fixtures.crossclass.duplicate.caller.AmbiguousCaller",
                "call",
                UnsupportedInterproceduralReason.AMBIGUOUS_CLASS);
        assertNoSourceFrom("fixtures.crossclass.duplicate.caller.AmbiguousCaller", "call");
    }

    @Test
    void bodylessClassMethodIsUnsupportedWithoutFailingProjectAnalysis() {
        ProjectCallResolution resolution = resolution(
                BODYLESS_CONTROLLER, "bodylessCall", "query");
        assertTrue(resolution.target().isEmpty());
        assertEquals(UnsupportedInterproceduralReason.NO_ANALYZABLE_BODY,
                resolution.unsupported().orElseThrow().reason());
        assertNoSourceFrom(BODYLESS_CONTROLLER, "bodylessCall");
    }

    @Test
    void bodylessMethodReturnRemainsUnknownAtCallerSink() {
        ProjectCallResolution resolution = resolution(
                BODYLESS_CONTROLLER, "bodylessReturn", "query");
        assertEquals(TaintState.UNKNOWN,
                result.methodAnalyses()
                        .get(methodId(BODYLESS_CONTROLLER, "bodylessReturn"))
                        .taintResult()
                        .taintOf(resolution.call())
                        .state());
        assertNoSourceFrom(BODYLESS_CONTROLLER, "bodylessReturn");
    }

    @Test
    void bodylessTargetDoesNotSuppressIndependentProjectFinding() {
        findingFrom(BODYLESS_CONTROLLER, "normal", REPOSITORY, "sql", SinkCategory.SQL_TEXT);
    }

    @Test
    void exactExternalFqnDoesNotFallBackToAmbiguousProjectSimpleName() {
        ProjectCallResolution resolution = resolution(EXACT_EXTERNAL_CALLER, "call", "run");
        assertTrue(resolution.target().isEmpty());
        assertEquals(UnsupportedInterproceduralReason.EXTERNAL_CLASS,
                resolution.unsupported().orElseThrow().reason());
        assertFalse(result.callResolutions().stream()
                .filter(call -> call.caller().equals(methodId(EXACT_EXTERNAL_CALLER, "call")))
                .flatMap(call -> call.unsupported().stream())
                .anyMatch(item -> item.reason() == UnsupportedInterproceduralReason.AMBIGUOUS_CLASS));
    }

    @Test
    void uniqueInterfaceImplementationUsesSourceHierarchy() {
        assertResolved(CONTROLLER, "interfaceReceiver",
                "fixtures.crossclass.external.UserPortImpl", "sql");
        findingFrom(CONTROLLER, "interfaceReceiver", REPOSITORY, "sql",
                SinkCategory.SQL_TEXT);
    }

    @Test
    void declaredBaseTypeDoesNotDispatchToChildOverride() {
        ProjectCallResolution resolution = resolution(CONTROLLER, "inheritedReceiver", "forward");
        assertEquals(BASE, resolution.target().orElseThrow().ownerQualifiedName());
        assertFalse(result.callResolutions().stream()
                .filter(call -> call.caller().equals(methodId(CONTROLLER, "inheritedReceiver")))
                .anyMatch(call -> call.target().map(target ->
                        target.ownerQualifiedName().equals(CHILD)).orElse(false)));
        assertNoSourceFrom(CONTROLLER, "inheritedReceiver");
    }

    @Test
    void ambiguousOverloadNeverSelectsFirstCandidate() {
        assertUnsupported(CONTROLLER, "ambiguous",
                UnsupportedInterproceduralReason.UNKNOWN_ARGUMENT_TYPE);
        assertNoSourceFrom(CONTROLLER, "ambiguous");
    }

    @Test
    void incompatibleCrossClassArgumentTypeIsRejected() {
        assertUnsupported(CONTROLLER, "incompatible",
                UnsupportedInterproceduralReason.INCOMPATIBLE_ARGUMENT_TYPE);
        assertNoSourceFrom(CONTROLLER, "incompatible");
    }

    @Test
    void crossClassCycleIsUnsupportedAndFinite() {
        assertUnsupported(CYCLE_A, "a", UnsupportedInterproceduralReason.RECURSIVE_CALL);
        assertUnsupported(CYCLE_B, "b", UnsupportedInterproceduralReason.RECURSIVE_CALL);
        assertEquals(MethodReturnDependencyKind.UNKNOWN,
                result.methodSummaries().get(methodId(CYCLE_A, "a")).returnDependency().kind());
        assertEquals(MethodReturnDependencyKind.UNKNOWN,
                result.methodSummaries().get(methodId(CYCLE_B, "b")).returnDependency().kind());
    }

    @Test
    void springDataMethodNameIsNotInventedAsSqlSink() {
        assertUnsupported(CONTROLLER, "springData",
                UnsupportedInterproceduralReason.INTERFACE_DISPATCH);
        assertNoSourceFrom(CONTROLLER, "springData");
    }

    @ParameterizedTest
    @MethodSource("excludedContextSensitiveMethods")
    void contextSensitiveVulnerabilitiesAreNotGenericallyExtended(String methodName) {
        assertNoSourceFrom(CONTROLLER, methodName);
    }

    private static Stream<String> excludedContextSensitiveMethods() {
        return Stream.of("xss", "redirect", "upload", "xxe");
    }

    @Test
    void customStereotypeAnnotationIsNotDispatchEvidence() {
        assertTrue(result.classIndex().uniqueClass(
                "fixtures.crossclass.custom.CustomAnnotatedService").isPresent());
        assertUnsupported(CONTROLLER, "customAnnotationOnly",
                UnsupportedInterproceduralReason.EXTERNAL_CLASS);
    }

    @Test
    void duplicateFqnIsRetainedAsAmbiguousInsteadOfSelectingOne() {
        String fqn = "fixtures.crossclass.duplicatefqn.DuplicateFqn";
        assertEquals(2, result.classIndex().candidates(fqn).size());
        assertTrue(result.classIndex().uniqueClass(fqn).isEmpty());
        assertTrue(result.unsupported().stream()
                .anyMatch(item -> item.reason() == UnsupportedInterproceduralReason.AMBIGUOUS_CLASS
                        && item.detail().contains(fqn)));
    }

    @Test
    void methodIdentityIncludesOwnerClass() {
        ProjectMethodId service = methodId(SERVICE, "sql");
        ProjectMethodId repository = methodId(REPOSITORY, "sql");
        assertFalse(service.equals(repository));
        assertTrue(service.displayName().startsWith(SERVICE + "#sql("));
        assertTrue(repository.displayName().startsWith(REPOSITORY + "#sql("));
    }

    @Test
    void resultContainsOnlyFivePureTaintCategories() {
        Set<SinkCategory> supported = Set.of(
                SinkCategory.SQL_TEXT,
                SinkCategory.COMMAND_EXECUTION,
                SinkCategory.FILESYSTEM_PATH,
                SinkCategory.NETWORK_REQUEST_TARGET,
                SinkCategory.LDAP_FILTER);
        assertTrue(result.findings().stream()
                .allMatch(finding -> supported.contains(finding.sink().category())));
    }

    private static void assertResolved(
            String callerOwner, String callerMethod, String targetOwner, String targetMethod) {
        assertTrue(result.callResolutions().stream()
                .filter(call -> call.caller().equals(methodId(callerOwner, callerMethod)))
                .anyMatch(call -> call.target().map(target ->
                        target.ownerQualifiedName().equals(targetOwner)
                                && target.method().name().equals(targetMethod)).orElse(false)));
    }

    private static void assertUnsupported(
            String owner, String methodName, UnsupportedInterproceduralReason reason) {
        assertTrue(result.callResolutions().stream()
                .filter(call -> call.caller().equals(methodId(owner, methodName)))
                .flatMap(call -> call.unsupported().stream())
                .anyMatch(item -> item.reason() == reason), owner + "#" + methodName + " " + reason);
    }

    private static ProjectCallResolution resolution(
            String owner, String callerMethod, String calledMethod) {
        return result.callResolutions().stream()
                .filter(call -> call.caller().equals(methodId(owner, callerMethod)))
                .filter(call -> call.call().call().methodName().equals(calledMethod))
                .findFirst().orElseThrow();
    }

    private static Finding findingFrom(
            String sourceOwner,
            String sourceMethod,
            String sinkOwner,
            String sinkMethod,
            SinkCategory category) {
        MethodInfo source = method(sourceOwner, sourceMethod);
        MethodInfo sink = method(sinkOwner, sinkMethod);
        return result.findings().stream()
                .filter(finding -> finding.sink().category() == category)
                .filter(finding -> within(sink, finding.sink().location()))
                .filter(finding -> finding.sources().stream()
                        .anyMatch(item -> within(source, item.location())))
                .findFirst().orElseThrow(() -> new AssertionError(
                        "No finding from " + sourceOwner + "#" + sourceMethod
                                + " to " + sinkOwner + "#" + sinkMethod));
    }

    private static List<com.totalsecurity.sast.finding.FindingFlowStep> flowFrom(
            String owner, String methodName, Finding finding) {
        MethodInfo source = method(owner, methodName);
        return finding.flows().stream()
                .filter(flow -> within(source, flow.source().location()))
                .findFirst().orElseThrow().steps();
    }

    private static void assertNoSourceFrom(String owner, String methodName) {
        MethodInfo method = method(owner, methodName);
        assertTrue(result.findings().stream().flatMap(finding -> finding.sources().stream())
                .noneMatch(source -> within(method, source.location())));
    }

    private static ProjectMethodId methodId(String owner, String name) {
        List<ProjectMethodId> methods = result.methodSummaries().keySet().stream()
                .filter(id -> id.ownerQualifiedName().equals(owner))
                .filter(id -> id.method().name().equals(name))
                .toList();
        if (methods.size() != 1) {
            throw new IllegalArgumentException("Method is not unique: " + owner + "#" + name);
        }
        return methods.getFirst();
    }

    private static MethodInfo method(String owner, String name) {
        return methodId(owner, name).method();
    }

    private static boolean within(MethodInfo method, SourceLocation location) {
        return location.file().equals(method.location().file())
                && location.startLine() >= method.location().startLine()
                && location.startLine() <= method.location().endLine();
    }

    private static List<String> fixtureResources() {
        return List.of(
                "fixtures/crossclass/controller/UserController.java",
                "fixtures/crossclass/service/UserService.java",
                "fixtures/crossclass/service/SamePackageHelper.java",
                "fixtures/crossclass/repository/UserRepository.java",
                "fixtures/crossclass/repository/SpringDataRepository.java",
                "fixtures/crossclass/outbound/OutboundGateway.java",
                "fixtures/crossclass/external/OverloadService.java",
                "fixtures/crossclass/external/IntService.java",
                "fixtures/crossclass/external/AmbiguousService.java",
                "fixtures/crossclass/external/UserPort.java",
                "fixtures/crossclass/external/UserPortImpl.java",
                "fixtures/crossclass/external/BaseService.java",
                "fixtures/crossclass/external/ChildService.java",
                "fixtures/crossclass/context/ContextService.java",
                "fixtures/crossclass/cycle/CycleA.java",
                "fixtures/crossclass/cycle/CycleB.java",
                "fixtures/crossclass/bodyless/AbstractService.java",
                "fixtures/crossclass/bodyless/BodylessController.java",
                "fixtures/crossclass/exactexternal/ExternalCaller.java",
                "fixtures/crossclass/duplicate/one/DuplicateService.java",
                "fixtures/crossclass/duplicate/two/DuplicateService.java",
                "fixtures/crossclass/duplicate/caller/AmbiguousCaller.java",
                "fixtures/crossclass/duplicatefqn/a/DuplicateFqn.java",
                "fixtures/crossclass/duplicatefqn/b/DuplicateFqn.java",
                "fixtures/crossclass/custom/Service.java",
                "fixtures/crossclass/custom/CustomAnnotatedService.java");
    }

    private static Path fixturePath(String resource) throws URISyntaxException {
        var value = CrossClassInterproceduralAnalysisTest.class.getClassLoader().getResource(resource);
        if (value == null) {
            throw new IllegalStateException("STEP 19 fixture not found: " + resource);
        }
        return Path.of(value.toURI());
    }
}
