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
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.java.extractor.JavaSemanticExtractor;
import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import com.totalsecurity.sast.rule.RuleRegistry;
import com.totalsecurity.sast.rule.sink.SinkCategory;
import com.totalsecurity.sast.taint.TaintState;
import com.totalsecurity.sast.taint.model.MethodTaintModelPriority;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class SameClassInterproceduralAnalysisTest {
    private static JavaFileInfo file;
    private static ClassInfo type;
    private static SameClassInterproceduralResult result;

    @BeforeAll
    static void analyzeFixture() throws Exception {
        try (JavaSourceParser parser = new JavaSourceParser();
                ParsedJavaFile parsed = parser.parse(fixturePath())) {
            assertFalse(parsed.hasSyntaxErrors());
            file = new JavaSemanticExtractor().extract(parsed);
            type = file.types().stream()
                    .filter(candidate -> candidate.name().equals("SameClassInterproceduralFixture"))
                    .findFirst().orElseThrow();
        }
        result = new SameClassInterproceduralAnalysis()
                .analyze(file, type, RuleRegistry.javaSpringBackendDefaults());
    }

    @ParameterizedTest
    @MethodSource("supportedEntryToSinkFlows")
    void supportedPureTaintCategoriesCrossMethodBoundary(
            String entryMethod, String sinkMethod, SinkCategory category, String ruleId) {
        Finding finding = findingFrom(entryMethod, sinkMethod, category);
        assertEquals(ruleId, finding.ruleId());
        assertTrue(finding.flows().stream().flatMap(flow -> flow.steps().stream())
                .anyMatch(step -> step.kind() == FindingFlowStepKind.METHOD_CALL));
        assertTrue(finding.flows().stream().flatMap(flow -> flow.steps().stream())
                .anyMatch(step -> step.kind() == FindingFlowStepKind.PARAMETER_BINDING));
    }

    private static Stream<Arguments> supportedEntryToSinkFlows() {
        return Stream.of(
                Arguments.of("sqlEntry", "sqlHelper", SinkCategory.SQL_TEXT,
                        SqlInjectionDetector.RULE_ID),
                Arguments.of("commandEntry", "commandHelper", SinkCategory.COMMAND_EXECUTION,
                        CommandInjectionDetector.RULE_ID),
                Arguments.of("pathEntry", "pathHelper", SinkCategory.FILESYSTEM_PATH,
                        PathTraversalDetector.RULE_ID),
                Arguments.of("ssrfEntry", "ssrfHelper", SinkCategory.NETWORK_REQUEST_TARGET,
                        SsrfDetector.RULE_ID),
                Arguments.of("ldapEntry", "ldapHelper", SinkCategory.LDAP_FILTER,
                        LdapInjectionDetector.RULE_ID));
    }

    @Test
    void twoHopSummaryPreservesBothCallBoundariesAndPhysicalSink() {
        Finding finding = findingFrom("twoHopEntry", "hopB", SinkCategory.SQL_TEXT);
        long calls = finding.flows().stream()
                .filter(flow -> within(method("twoHopEntry"), flow.source().location()))
                .flatMap(flow -> flow.steps().stream())
                .filter(step -> step.kind() == FindingFlowStepKind.METHOD_CALL)
                .count();
        assertEquals(2, calls);
        assertEquals("executeQuery", finding.sink().methodName());
        assertTrue(within(method("hopB"), finding.sink().location()));
    }

    @ParameterizedTest
    @MethodSource("returnFlows")
    void calleeReturnSummaryFeedsCallerSink(String entryMethod, String calleeMethod) {
        Finding finding = findingFrom(entryMethod, entryMethod, SinkCategory.SQL_TEXT);
        assertTrue(finding.flows().stream().flatMap(flow -> flow.steps().stream())
                .anyMatch(step -> step.kind() == FindingFlowStepKind.METHOD_RETURN
                        && within(method(calleeMethod), step.location())));
    }

    @Test
    void threeLevelReturnProvenancePreservesEveryBoundaryInOrder() {
        Finding finding = findingFrom(
                "threeLevelReturnEntry", "threeLevelReturnEntry", SinkCategory.SQL_TEXT);
        List<String> boundaries = finding.flows().stream()
                .filter(flow -> within(method("threeLevelReturnEntry"), flow.source().location()))
                .findFirst().orElseThrow()
                .steps().stream()
                .filter(step -> step.kind() == FindingFlowStepKind.METHOD_CALL
                        || step.kind() == FindingFlowStepKind.PARAMETER_BINDING
                        || step.kind() == FindingFlowStepKind.METHOD_RETURN)
                .map(step -> step.summary())
                .toList();
        assertEquals(List.of(
                "Same-class call threeLevelReturnEntry -> returnA",
                "Bind argument 0 to returnA parameter value",
                "Same-class call returnA -> returnB",
                "Bind argument 0 to returnB parameter value",
                "Same-class call returnB -> returnC",
                "Bind argument 0 to returnC parameter value",
                "Return from returnC",
                "Return from returnB",
                "Return from returnA"), boundaries);
    }

    private static Stream<Arguments> returnFlows() {
        return Stream.of(
                Arguments.of("returnEntry", "buildSql"),
                Arguments.of("trimReturnEntry", "trimValue"));
    }

    @Test
    void selectedParameterDependencyContainsOnlyUsedParameter() {
        SameClassMethodSummary summary = summary("selectedHelper");
        InterproceduralSinkDependency dependency = only(summary.sinkDependencies());
        assertEquals(Set.of(1), dependency.parameterIndexes());
        assertTrue(findingFrom("selectedEntry", "selectedHelper", SinkCategory.SQL_TEXT)
                .sources().stream().allMatch(source -> source.summary().contains("input")));
    }

    @Test
    void thisQualifiedCallIsResolved() {
        assertTrue(result.callResolutions().stream()
                .anyMatch(call -> call.caller().name().equals("thisEntry")
                        && call.target().map(target -> target.name().equals("sqlHelper")).orElse(false)));
        findingFrom("thisEntry", "sqlHelper", SinkCategory.SQL_TEXT);
    }

    @Test
    void exactCurrentClassTypeReferenceResolvesStaticStyleCall() {
        assertTrue(result.callResolutions().stream()
                .anyMatch(call -> call.caller().name().equals("staticStyleEntry")
                        && call.target().map(target -> target.name().equals("staticStyleHelper"))
                                .orElse(false)));
        findingFrom("staticStyleEntry", "staticStyleHelper", SinkCategory.SQL_TEXT);
    }

    @Test
    void classNameShadowingValueReceiversAreNotSameClassCalls() {
        for (String methodName : List.of("classNameLocalShadow", "classNameParameterShadow")) {
            assertTrue(result.callResolutions().stream()
                    .filter(call -> call.caller().name().equals(methodName))
                    .anyMatch(call -> call.status() == SameClassCallStatus.UNSUPPORTED
                            && call.unsupported().orElseThrow().reason()
                                    == UnsupportedInterproceduralReason.DYNAMIC_RECEIVER));
            assertFalse(result.callResolutions().stream()
                    .filter(call -> call.caller().name().equals(methodName))
                    .anyMatch(call -> call.target()
                            .map(target -> target.name().equals("staticStyleHelper"))
                            .orElse(false)));
            assertNoSourceFrom(methodName);
        }
    }

    @Test
    void exactTypesChooseTheStringOverload() {
        SameClassCallResolution resolution = result.callResolutions().stream()
                .filter(call -> call.caller().name().equals("overloadEntry"))
                .findFirst().orElseThrow();
        assertTrue(resolution.target().isPresent());
        assertEquals("String", resolution.target().orElseThrow().parameters().getFirst().type());
        Finding finding = result.findings().stream()
                .filter(candidate -> candidate.sink().category() == SinkCategory.SQL_TEXT)
                .filter(candidate -> within(method("overloaded", "String"),
                        candidate.sink().location()))
                .filter(candidate -> candidate.sources().stream()
                        .anyMatch(source -> within(method("overloadEntry"), source.location())))
                .findFirst().orElseThrow();
        assertEquals(SqlInjectionDetector.RULE_ID, finding.ruleId());
    }

    @ParameterizedTest
    @MethodSource("branchFlows")
    void callerAndCalleeBranchesUseMayTaint(String entryMethod, String sinkMethod) {
        findingFrom(entryMethod, sinkMethod, SinkCategory.SQL_TEXT);
    }

    private static Stream<Arguments> branchFlows() {
        return Stream.of(
                Arguments.of("calleeBranchEntry", "calleeBranch"),
                Arguments.of("callerBranchEntry", "sqlHelper"));
    }

    @Test
    void multipleOriginsAtOnePhysicalSinkAreDeduplicatedAndPreserved() {
        Finding finding = findingFrom("multipleOrigins", "sqlHelper", SinkCategory.SQL_TEXT);
        assertEquals(1, result.findings().stream()
                .filter(candidate -> candidate.ruleId().equals(SqlInjectionDetector.RULE_ID))
                .filter(candidate -> candidate.sink().location().equals(finding.sink().location()))
                .count());
        assertTrue(finding.sources().stream()
                .anyMatch(source -> source.summary().contains("left")));
        assertTrue(finding.sources().stream()
                .anyMatch(source -> source.summary().contains("right")));
    }

    @Test
    void sourceLocationIsCallerAndSinkLocationIsCallee() {
        Finding finding = findingFrom("sqlEntry", "sqlHelper", SinkCategory.SQL_TEXT);
        assertTrue(finding.sources().stream()
                .anyMatch(source -> within(method("sqlEntry"), source.location())));
        assertTrue(within(method("sqlHelper"), finding.sink().location()));
    }

    @Test
    void cleanAndOverwrittenArgumentsDoNotAddOriginsToHelperSink() {
        Finding helperFinding = findingAt("sqlHelper", SinkCategory.SQL_TEXT);
        assertFalse(helperFinding.sources().stream()
                .anyMatch(source -> within(method("cleanOverwrite"), source.location())));
        assertTrue(method("cleanArgument").parameters().isEmpty());
    }

    @Test
    void fixedReturnIsCleanAndUnknownReturnStaysUnknown() {
        assertEquals(MethodReturnDependencyKind.CLEAN,
                summary("fixedReturn").returnDependency().kind());
        assertEquals(MethodReturnDependencyKind.UNKNOWN,
                summary("unknownReturn").returnDependency().kind());
        assertNoFindingAt("fixedReturnEntry", SinkCategory.SQL_TEXT);
        assertNoFindingAt("unknownReturnEntry", SinkCategory.SQL_TEXT);
    }

    @ParameterizedTest
    @MethodSource("unsupportedCalls")
    void unsupportedCallsAreRecordedWithoutPropagation(
            String methodName, UnsupportedInterproceduralReason reason) {
        assertTrue(result.unsupported().stream()
                .anyMatch(item -> item.reason() == reason
                        && within(method(methodName), item.location())));
    }

    private static Stream<Arguments> unsupportedCalls() {
        return Stream.of(
                Arguments.of("externalReceiver", UnsupportedInterproceduralReason.DYNAMIC_RECEIVER),
                Arguments.of("ambiguousEntry", UnsupportedInterproceduralReason.UNKNOWN_ARGUMENT_TYPE),
                Arguments.of("superEntry", UnsupportedInterproceduralReason.INHERITED_METHOD),
                Arguments.of("wrongArityEntry", UnsupportedInterproceduralReason.WRONG_ARITY),
                Arguments.of("incompatibleTypeEntry",
                        UnsupportedInterproceduralReason.INCOMPATIBLE_ARGUMENT_TYPE),
                Arguments.of("selfRecursive", UnsupportedInterproceduralReason.RECURSIVE_CALL),
                Arguments.of("mutualA", UnsupportedInterproceduralReason.RECURSIVE_CALL));
    }

    @Test
    void recursiveSummariesAreExcludedAndDoNotProduceFalseFindings() {
        assertEquals(MethodReturnDependencyKind.UNKNOWN,
                summary("selfRecursive").returnDependency().kind());
        assertTrue(summary("selfRecursive").sinkDependencies().isEmpty());
        assertTrue(summary("mutualA").sinkDependencies().isEmpty());
        assertNoSourceFrom("selfEntry");
        assertNoSourceFrom("mutualEntry");
    }

    @Test
    void recursiveReturnRemainsUnsupportedWithoutProvenanceExpansion() {
        assertEquals(MethodReturnDependencyKind.UNKNOWN,
                summary("recursiveReturn").returnDependency().kind());
        assertTrue(result.unsupported().stream()
                .anyMatch(item -> item.reason() == UnsupportedInterproceduralReason.RECURSIVE_CALL
                        && within(method("recursiveReturn"), item.location())));
        assertNoFindingAt("recursiveReturnEntry", SinkCategory.SQL_TEXT);
    }

    @ParameterizedTest
    @MethodSource("excludedContextSensitiveHelpers")
    void contextSensitiveDetectorsAreNotAutomaticallyExpanded(String entryMethod) {
        assertNoSourceFrom(entryMethod);
    }

    private static Stream<String> excludedContextSensitiveHelpers() {
        return Stream.of("xssEntry", "redirectEntry", "uploadEntry", "xxeEntry");
    }

    @Test
    void existingLocalFindingRemainsExactlyOne() {
        MethodInfo local = method("localSql");
        assertEquals(1, result.findings().stream()
                .filter(finding -> finding.ruleId().equals(SqlInjectionDetector.RULE_ID))
                .filter(finding -> within(local, finding.sink().location()))
                .count());
    }

    @Test
    void sameClassPriorityIsBelowSanitizerAndAboveFrameworkModels() {
        assertTrue(MethodTaintModelPriority.SANITIZER.rank()
                > MethodTaintModelPriority.SAME_CLASS_INTERPROCEDURAL.rank());
        assertTrue(MethodTaintModelPriority.SAME_CLASS_INTERPROCEDURAL.rank()
                > MethodTaintModelPriority.FRAMEWORK_SPECIFIC_PROPAGATION.rank());
    }

    @Test
    void resultContainsOnlyTheFiveSupportedSinkCategories() {
        Set<SinkCategory> supported = Set.of(
                SinkCategory.SQL_TEXT,
                SinkCategory.COMMAND_EXECUTION,
                SinkCategory.FILESYSTEM_PATH,
                SinkCategory.NETWORK_REQUEST_TARGET,
                SinkCategory.LDAP_FILTER);
        assertTrue(result.findings().stream()
                .allMatch(finding -> supported.contains(finding.sink().category())));
    }

    private static Finding findingFrom(
            String sourceMethod, String sinkMethod, SinkCategory category) {
        return result.findings().stream()
                .filter(finding -> finding.sink().category() == category)
                .filter(finding -> within(method(sinkMethod), finding.sink().location()))
                .filter(finding -> finding.sources().stream()
                        .anyMatch(source -> within(method(sourceMethod), source.location())))
                .findFirst().orElseThrow(() -> new AssertionError(
                        "No finding from " + sourceMethod + " to " + sinkMethod));
    }

    private static Finding findingAt(String sinkMethod, SinkCategory category) {
        return result.findings().stream()
                .filter(finding -> finding.sink().category() == category)
                .filter(finding -> within(method(sinkMethod), finding.sink().location()))
                .findFirst().orElseThrow();
    }

    private static void assertNoFindingAt(String sinkMethod, SinkCategory category) {
        assertTrue(result.findings().stream()
                .filter(finding -> finding.sink().category() == category)
                .noneMatch(finding -> within(method(sinkMethod), finding.sink().location())));
    }

    private static void assertNoSourceFrom(String methodName) {
        MethodInfo method = method(methodName);
        assertTrue(result.findings().stream().flatMap(finding -> finding.sources().stream())
                .noneMatch(source -> within(method, source.location())));
    }

    private static SameClassMethodSummary summary(String methodName) {
        return result.methodSummaries().get(method(methodName));
    }

    private static MethodInfo method(String name) {
        List<MethodInfo> matches = type.methods().stream()
                .filter(method -> method.name().equals(name)).toList();
        if (matches.size() != 1) {
            throw new IllegalArgumentException("Method is not unique: " + name);
        }
        return matches.getFirst();
    }

    private static MethodInfo method(String name, String firstParameterType) {
        return type.methods().stream()
                .filter(method -> method.name().equals(name))
                .filter(method -> !method.parameters().isEmpty())
                .filter(method -> method.parameters().getFirst().type().equals(firstParameterType))
                .findFirst().orElseThrow();
    }

    private static boolean within(MethodInfo method, com.totalsecurity.sast.ir.SourceLocation location) {
        return location.startLine() >= method.location().startLine()
                && location.startLine() <= method.location().endLine();
    }

    private static <T> T only(List<T> values) {
        assertEquals(1, values.size());
        return values.getFirst();
    }

    private static Path fixturePath() throws URISyntaxException {
        var resource = SameClassInterproceduralAnalysisTest.class.getClassLoader()
                .getResource("fixtures/SameClassInterproceduralFixture.java");
        if (resource == null) {
            throw new IllegalStateException("STEP 18 fixture not found");
        }
        return Path.of(resource.toURI());
    }
}
