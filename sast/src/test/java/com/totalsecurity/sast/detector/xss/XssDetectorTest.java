package com.totalsecurity.sast.detector.xss;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.cfg.ControlFlowGraph;
import com.totalsecurity.sast.cfg.ControlFlowGraphBuilder;
import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.ReachingDefinitionsAnalysis;
import com.totalsecurity.sast.finding.FindingFlowStepKind;
import com.totalsecurity.sast.finding.FindingSeverity;
import com.totalsecurity.sast.finding.XssEvidenceKind;
import com.totalsecurity.sast.finding.XssFinding;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.java.extractor.JavaSemanticExtractor;
import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import com.totalsecurity.sast.rule.RuleAwareTaintAnalysis;
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import com.totalsecurity.sast.rule.RuleRegistry;
import com.totalsecurity.sast.rule.sink.JavaPrintWriterResponseBodySinkRule;
import com.totalsecurity.sast.rule.sink.SinkCategory;
import com.totalsecurity.sast.rule.sink.SinkMatch;
import com.totalsecurity.sast.taint.TaintState;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class XssDetectorTest {
    private static final RuleRegistry RULES = RuleRegistry.javaSpringBackendDefaults();
    private static final XssDetector DETECTOR = new XssDetector();
    private static final ServletHtmlResponseAnalyzer ANALYZER =
            new ServletHtmlResponseAnalyzer();
    private static JavaFileInfo file;
    private static ClassInfo type;
    private static Map<String, MethodInfo> methods;

    @BeforeAll
    static void loadFixture() throws Exception {
        try (JavaSourceParser parser = new JavaSourceParser();
                ParsedJavaFile parsed = parser.parse(fixturePath())) {
            assertFalse(parsed.hasSyntaxErrors());
            file = new JavaSemanticExtractor().extract(parsed);
            type = file.types().stream()
                    .filter(candidate -> candidate.name().equals("XssFixture"))
                    .findFirst()
                    .orElseThrow();
            methods = type.methods().stream()
                    .collect(Collectors.toUnmodifiableMap(MethodInfo::name, Function.identity()));
        }
    }

    @ParameterizedTest
    @MethodSource("positiveFlows")
    void rawExternalInputInProvenHtmlResponseProducesFinding(String methodName) {
        Analysis analysis = analyze(methodName);
        assertEquals(1, analysis.findings().size());
        HtmlResponseOutput output = only(analysis.outputs());
        assertTrue(output.writerLineageConfirmed());
        assertEquals(HttpResponseContentType.HTML, output.contentType());
        assertEquals(HtmlOutputSafety.RAW_TAINTED, output.outputSafety());
        assertTrue(output.confirmed());
    }

    private static Stream<String> positiveFlows() {
        return Stream.of(
                "requestParam",
                "pathVariable",
                "requestBody",
                "requestHeader",
                "cookieValue",
                "servletSource",
                "localAssignment",
                "throughTrim",
                "fixedPrefix",
                "fixedSuffix",
                "wrapped",
                "localWriter",
                "compactCharset",
                "spacedCharset",
                "branchTaint",
                "loopTaint",
                "multipleSources",
                "jsonThenHtml",
                "repeatedHtml",
                "allBranchesHtml",
                "htmlBeforeLoop");
    }

    @ParameterizedTest
    @MethodSource("writerApis")
    void exactPrintWriterStringApiIsResponseBodySink(
            String methodName, String expectedMethod) {
        SinkMatch sink = only(analyze(methodName).result().sinkMatches());
        assertEquals(JavaPrintWriterResponseBodySinkRule.ID, sink.ruleId());
        assertEquals(SinkCategory.HTTP_RESPONSE_BODY, sink.category());
        assertEquals(expectedMethod, sink.call().call().methodName());
        assertEquals(Set.of(0), sink.sensitiveArgumentIndexes());
    }

    private static Stream<Arguments> writerApis() {
        return Stream.of(
                Arguments.of("requestParam", "write"),
                Arguments.of("pathVariable", "print"),
                Arguments.of("requestBody", "println"));
    }

    @Test
    void directNestedGetWriterHasExactWriterLineage() {
        HtmlResponseOutput output = only(analyze("requestParam").outputs());
        assertTrue(output.writerLineageConfirmed());
        assertTrue(output.evidence().stream()
                .anyMatch(item -> item.kind() == XssEvidenceKind.WRITER_DERIVATION));
    }

    @ParameterizedTest
    @MethodSource("nonHtmlContexts")
    void nonHtmlOrUnprovenContextDoesNotProduceFinding(
            String methodName, HttpResponseContentType expected) {
        Analysis analysis = analyze(methodName);
        assertTrue(analysis.findings().isEmpty());
        assertEquals(expected, only(analysis.outputs()).contentType());
    }

    private static Stream<Arguments> nonHtmlContexts() {
        return Stream.of(
                Arguments.of("textPlain", HttpResponseContentType.NON_HTML),
                Arguments.of("json", HttpResponseContentType.NON_HTML),
                Arguments.of("misleadingContentType", HttpResponseContentType.NON_HTML),
                Arguments.of("unset", HttpResponseContentType.UNSET),
                Arguments.of("nonLiteralContentType", HttpResponseContentType.UNKNOWN),
                Arguments.of("htmlThenJson", HttpResponseContentType.NON_HTML),
                Arguments.of("mixedContentBranch", HttpResponseContentType.UNKNOWN),
                Arguments.of("htmlOrUnset", HttpResponseContentType.UNKNOWN));
    }

    @Test
    void laterContentTypeWriteStronglyOverwritesEarlierState() {
        assertEquals(
                HttpResponseContentType.NON_HTML,
                only(analyze("htmlThenJson").outputs()).contentType());
        assertEquals(
                HttpResponseContentType.HTML,
                only(analyze("jsonThenHtml").outputs()).contentType());
    }

    @Test
    void repeatedHtmlWriteRetainsOnlyEffectiveContentTypeEvidence() {
        XssFinding finding = only(analyze("repeatedHtml").findings());
        assertEquals(
                1,
                finding.contextEvidence().stream()
                        .filter(item -> item.kind() == XssEvidenceKind.CONTENT_TYPE)
                        .count());
    }

    @Test
    void allBranchPathsMustProveHtml() {
        assertEquals(
                HttpResponseContentType.HTML,
                only(analyze("allBranchesHtml").outputs()).contentType());
        assertEquals(
                HttpResponseContentType.UNKNOWN,
                only(analyze("mixedContentBranch").outputs()).contentType());
    }

    @Test
    void cleanLiteralInHtmlContextIsNotReported() {
        Analysis analysis = analyze("fixedLiteral");
        assertEquals(HtmlOutputSafety.CLEAN, only(analysis.outputs()).outputSafety());
        assertTrue(analysis.findings().isEmpty());
    }

    @ParameterizedTest
    @MethodSource("escapedOutputs")
    void exactSpringHtmlEscapeIsXssSpecificSafeOutput(String methodName) {
        Analysis analysis = analyze(methodName);
        assertEquals(HtmlOutputSafety.HTML_ESCAPED, only(analysis.outputs()).outputSafety());
        assertTrue(analysis.findings().isEmpty());
    }

    private static Stream<String> escapedOutputs() {
        return Stream.of("escapedDirect", "escapedLocal");
    }

    @Test
    void springHtmlEscapeIsNotAGenericTaintSanitizer() {
        Analysis analysis = analyze("escapedDirect");
        SinkMatch sink = only(analysis.result().sinkMatches());
        assertEquals(TaintState.UNKNOWN, analysis.result().sinkArgumentTaint(sink, 0).state());
        assertEquals(HtmlOutputSafety.HTML_ESCAPED, only(analysis.outputs()).outputSafety());
    }

    @Test
    void arbitraryEscapeNameRemainsUnknown() {
        Analysis analysis = analyze("arbitraryEscape");
        assertEquals(HtmlOutputSafety.UNKNOWN, only(analysis.outputs()).outputSafety());
        assertTrue(analysis.findings().isEmpty());
    }

    @Test
    void customHtmlEscapeNameRemainsUnknown() {
        Analysis analysis = analyze("customHtmlUtils");
        assertEquals(HtmlOutputSafety.UNKNOWN, only(analysis.outputs()).outputSafety());
        assertTrue(analysis.findings().isEmpty());
    }

    @ParameterizedTest
    @MethodSource("excludedFlows")
    void excludedOrUnlinkedOutputDoesNotProduceFinding(String methodName) {
        assertTrue(analyze(methodName).findings().isEmpty());
    }

    private static Stream<String> excludedFlows() {
        return Stream.of(
                "customHtmlUtils",
                "customResponse",
                "legacyResponse",
                "customWriter",
                "unrelatedPrintWriter",
                "differentResponse",
                "ordinaryMethod",
                "servletOutputStream",
                "responseBodyReturn",
                "restControllerReturn",
                "thymeleafModel");
    }

    @ParameterizedTest
    @MethodSource("unlinkedPrintWriters")
    void exactPrintWriterWithoutJakartaResponseLineageIsNotConfirmed(String methodName) {
        HtmlResponseOutput output = only(analyze(methodName).outputs());
        assertFalse(output.writerLineageConfirmed());
        assertTrue(analyze(methodName).findings().isEmpty());
    }

    private static Stream<String> unlinkedPrintWriters() {
        return Stream.of(
                "customResponse",
                "legacyResponse",
                "unrelatedPrintWriter");
    }

    @Test
    void multipleOriginsProduceOneFindingWithAllFlows() {
        XssFinding finding = only(analyze("multipleSources").findings());
        assertEquals(2, finding.sources().size());
        assertEquals(2, finding.flows().size());
        assertEquals(
                Set.of("SPRING_MVC_REQUEST_PARAM", "SPRING_MVC_REQUEST_HEADER"),
                finding.sources().stream()
                        .map(source -> source.sourceRuleId())
                        .collect(Collectors.toSet()));
    }

    @Test
    void findingMetadataAndStructuredEvidenceAreExact() {
        XssFinding finding = only(analyze("requestParam").findings());
        assertEquals(XssDetector.RULE_ID, finding.ruleId());
        assertEquals("Cross-Site Scripting (XSS)", finding.vulnerabilityType());
        assertEquals("CWE-79", finding.cwe());
        assertEquals(FindingSeverity.MEDIUM, finding.severity());
        assertEquals(ServletHtmlResponseAnalyzer.RESPONSE_TYPE, finding.responseType());
        assertEquals(SinkCategory.HTTP_RESPONSE_BODY, finding.sink().category());
        assertEquals("write", finding.sink().methodName());
        assertEquals(0, finding.sink().argumentIndex());
        assertEquals(XssDetector.EVIDENCE, finding.evidence());
        assertEquals(finding.sink().location(), finding.outputLocation());
        assertEquals(
                Set.of(
                        XssEvidenceKind.CONTENT_TYPE,
                        XssEvidenceKind.WRITER_DERIVATION,
                        XssEvidenceKind.OUTPUT),
                finding.contextEvidence().stream()
                        .map(item -> item.kind())
                        .collect(Collectors.toSet()));
    }

    @Test
    void trimConcatenationAndHtmlSinkRemainInFlow() {
        XssFinding trimFinding = only(analyze("throughTrim").findings());
        XssFinding wrappedFinding = only(analyze("wrapped").findings());
        assertTrue(trimFinding.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().equals("Return value of trim")));
        assertTrue(wrappedFinding.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().equals("Binary expression +")));
        assertEquals(
                FindingFlowStepKind.SINK,
                wrappedFinding.flows().getFirst().steps().getLast().kind());
    }

    private static Analysis analyze(String methodName) {
        MethodInfo method = Optional.ofNullable(methods.get(methodName)).orElseThrow();
        ControlFlowGraph graph = new ControlFlowGraphBuilder().build(method);
        DataFlowResult dataFlow = new ReachingDefinitionsAnalysis().analyze(graph);
        RuleAwareTaintResult result =
                new RuleAwareTaintAnalysis().analyze(file, type, method, dataFlow, RULES);
        return new Analysis(
                result,
                ANALYZER.analyze(file, type, method, result),
                DETECTOR.detect(file, type, method, result));
    }

    private static <T> T only(List<T> values) {
        assertEquals(1, values.size());
        return values.getFirst();
    }

    private static Path fixturePath() throws URISyntaxException {
        var resource = XssDetectorTest.class.getClassLoader().getResource("fixtures/XssFixture.java");
        if (resource == null) {
            throw new IllegalStateException("STEP 16 fixture not found");
        }
        return Path.of(resource.toURI());
    }

    private record Analysis(
            RuleAwareTaintResult result,
            List<HtmlResponseOutput> outputs,
            List<XssFinding> findings) {}
}
