package com.totalsecurity.sast.detector.xxe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.cfg.ControlFlowGraph;
import com.totalsecurity.sast.cfg.ControlFlowGraphBuilder;
import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.ReachingDefinitionsAnalysis;
import com.totalsecurity.sast.finding.ConfigurationEvidence;
import com.totalsecurity.sast.finding.ConfigurationFinding;
import com.totalsecurity.sast.finding.FindingResult;
import com.totalsecurity.sast.finding.FindingSeverity;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import com.totalsecurity.sast.java.extractor.JavaSemanticExtractor;
import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import com.totalsecurity.sast.rule.context.CallSiteContextResolver;
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

class XxeDetectorTest {
    private static final XxeDetector DETECTOR = new XxeDetector();
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
                    .filter(candidate -> candidate.name().equals("XxeFixture"))
                    .findFirst()
                    .orElseThrow();
            methods = type.methods().stream()
                    .collect(Collectors.toUnmodifiableMap(MethodInfo::name, Function.identity()));
        }
    }

    @ParameterizedTest
    @MethodSource("provenExternalResolutionPaths")
    void fullyProvenExternalResolutionPathProducesOneFinding(
            String methodName, ExternalResolutionPath expectedPath, String expectedAccess) {
        ConfigurationFinding finding = only(analyze(methodName).findings());
        assertTrue(finding.evidence().contains(expectedPath.name()));
        ConfigurationEvidence access = finding.configurations().stream()
                .filter(evidence -> evidence.configurationKey().equals(
                        "http://javax.xml.XMLConstants/property/accessExternalDTD"))
                .findFirst()
                .orElseThrow();
        assertEquals(expectedAccess, access.configuredValue());
    }

    private static Stream<Arguments> provenExternalResolutionPaths() {
        return Stream.of(
                Arguments.of("generalEntityProven", ExternalResolutionPath.GENERAL_ENTITY, "all"),
                Arguments.of("parameterEntityProven", ExternalResolutionPath.PARAMETER_ENTITY, "file"),
                Arguments.of("externalDtdProven", ExternalResolutionPath.EXTERNAL_DTD, "http"));
    }

    @Test
    void multipleProvenPathsProduceOneFindingWithAllEvidence() {
        ConfigurationFinding finding = only(analyze("multipleProvenPaths").findings());
        assertEquals(5, finding.configurations().size());
        assertEquals(Set.of(
                        "http://apache.org/xml/features/disallow-doctype-decl",
                        "http://xml.org/sax/features/external-general-entities",
                        "http://xml.org/sax/features/external-parameter-entities",
                        "http://apache.org/xml/features/nonvalidating/load-external-dtd",
                        "http://javax.xml.XMLConstants/property/accessExternalDTD"),
                finding.configurations().stream()
                        .map(ConfigurationEvidence::configurationKey)
                        .collect(Collectors.toSet()));
        assertTrue(finding.evidence().contains("GENERAL_ENTITY"));
        assertTrue(finding.evidence().contains("PARAMETER_ENTITY"));
        assertTrue(finding.evidence().contains("EXTERNAL_DTD"));
    }

    @Test
    void safeThenUnsafeUsesFinalUnsafeState() {
        assertEquals(1, analyze("safeThenUnsafe").findings().size());
    }

    @Test
    void accessDenyThenAllowUsesFinalAllowState() {
        ConfigurationFinding finding = only(analyze("accessDenyThenAllow").findings());
        ConfigurationEvidence access = finding.configurations().stream()
                .filter(evidence -> evidence.configurationKey().equals(
                        "http://javax.xml.XMLConstants/property/accessExternalDTD"))
                .findFirst()
                .orElseThrow();
        assertEquals("file,http", access.configuredValue());
    }

    @Test
    void onlyBuilderFromUnsafeFactoryProducesFinding() {
        Analysis analysis = analyze("differentFactories");
        ConfigurationFinding finding = only(analysis.findings());
        List<MethodCallExpression> parses = calls(analysis, "parse");
        assertEquals(2, parses.size());
        assertEquals(parses.get(1).location(), finding.primaryLocation());
    }

    @Test
    void distinctBuilderLineageIsNotConfused() {
        Analysis analysis = analyze("differentBuilders");
        ConfigurationFinding finding = only(analysis.findings());
        List<MethodCallExpression> parses = calls(analysis, "parse");
        assertEquals(2, parses.size());
        assertEquals(parses.get(1).location(), finding.primaryLocation());
    }

    @ParameterizedTest
    @MethodSource("negativeCases")
    void unsupportedOrNotConfirmedCaseProducesNoFinding(String methodName) {
        assertTrue(analyze(methodName).findings().isEmpty());
    }

    private static Stream<String> negativeCases() {
        return Stream.of(
                "factoryOnly",
                "unsafeWithoutParse",
                "safeConfiguration",
                "unsafeThenSafe",
                "noConfiguration",
                "customFactory",
                "customBuilder",
                "configurationAfterBuilder",
                "mixedLineage",
                "arbitraryFeature",
                "arbitraryBooleanMethod",
                "branchAmbiguous",
                "loopAmbiguous",
                "accessBranchAmbiguous",
                "accessLoopAmbiguous",
                "disallowDoctypeUnsafe",
                "externalGeneralUnsafe",
                "externalParameterUnsafe",
                "externalDtdUnsafe",
                "xIncludeUnsafe",
                "expandEntitiesUnsafe",
                "generalAccessDenied",
                "doctypeDeniedGeneral",
                "generalUnknown",
                "accessUnknown",
                "generalAccessUnset",
                "customAccessProperty",
                "accessAllowThenDeny",
                "accessAfterBuilder",
                "safeExternalFeaturesWithDoctypeAllowed",
                "doctypeDeniedExpand");
    }

    @Test
    void unsafeThenSafeUsesFinalSafeState() {
        assertTrue(analyze("unsafeThenSafe").findings().isEmpty());
    }

    @Test
    void missingConfigurationDoesNotInferProviderDefaults() {
        assertTrue(analyze("noConfiguration").findings().isEmpty());
    }

    @Test
    void configurationAfterBuilderDoesNotRetroactivelyChangeSnapshot() {
        assertTrue(analyze("configurationAfterBuilder").findings().isEmpty());
        assertTrue(analyze("accessAfterBuilder").findings().isEmpty());
    }

    @Test
    void exactFeatureUriIsRequired() {
        assertTrue(analyze("arbitraryFeature").findings().isEmpty());
    }

    @Test
    void branchAndLoopAmbiguityAreNotConfirmed() {
        assertTrue(analyze("branchAmbiguous").findings().isEmpty());
        assertTrue(analyze("loopAmbiguous").findings().isEmpty());
    }

    @Test
    void supportedInputStreamOverloadIsAParserUse() {
        assertEquals(1, analyze("inputStreamOverload").findings().size());
    }

    @Test
    void findingMetadataAndTypesArePreserved() {
        ConfigurationFinding finding = only(analyze("generalEntityProven").findings());
        FindingResult common = finding;
        assertEquals(XxeDetector.RULE_ID, common.ruleId());
        assertEquals("XML External Entity (XXE)", common.vulnerabilityType());
        assertEquals("CWE-611", common.cwe());
        assertEquals(FindingSeverity.HIGH, common.severity());
        assertEquals("javax.xml.parsers.DocumentBuilderFactory", finding.factoryType());
        assertEquals("javax.xml.parsers.DocumentBuilder", finding.parserType());
    }

    @Test
    void primaryLocationIsParseAndCreationLocationIsBuilderFactoryCall() {
        Analysis analysis = analyze("generalEntityProven");
        ConfigurationFinding finding = only(analysis.findings());
        assertEquals(only(calls(analysis, "parse")).location(), finding.primaryLocation());
        assertEquals(only(calls(analysis, "parse")).location(), finding.parserUseLocation());
        assertEquals(only(calls(analysis, "newDocumentBuilder")).location(),
                finding.parserCreationLocation());
    }

    @Test
    void configurationLocationAndExactValueArePreserved() {
        Analysis analysis = analyze("generalEntityProven");
        ConfigurationFinding finding = only(analysis.findings());
        ConfigurationEvidence evidence = finding.configurations().stream()
                .filter(item -> item.configurationKey().equals(
                        "http://apache.org/xml/features/disallow-doctype-decl"))
                .findFirst()
                .orElseThrow();
        assertTrue(calls(analysis, "setFeature").stream()
                .anyMatch(call -> call.location().equals(evidence.location())));
        assertEquals("DocumentBuilderFactory.setFeature", evidence.api());
        assertEquals("false", evidence.configuredValue());
    }

    @Test
    void evidenceDoesNotClaimAttackerControlledXml() {
        ConfigurationFinding finding = only(analyze("generalEntityProven").findings());
        assertTrue(finding.evidence().contains("not independently established"));
        assertFalse(finding.evidence().contains("tainted input reaches"));
    }

    private static Analysis analyze(String methodName) {
        MethodInfo method = Optional.ofNullable(methods.get(methodName)).orElseThrow();
        ControlFlowGraph graph = new ControlFlowGraphBuilder().build(method);
        DataFlowResult dataFlow = new ReachingDefinitionsAnalysis().analyze(graph);
        return new Analysis(method, dataFlow, DETECTOR.detect(file, type, method, dataFlow));
    }

    private static List<MethodCallExpression> calls(Analysis analysis, String methodName) {
        return new CallSiteContextResolver(file, type, analysis.method(), analysis.dataFlow())
                .callSites().stream()
                .filter(call -> call.methodName().equals(methodName))
                .map(call -> call.call())
                .sorted(java.util.Comparator.comparingInt(call -> call.location().startLine()))
                .toList();
    }

    private static <T> T only(List<T> values) {
        assertEquals(1, values.size());
        return values.getFirst();
    }

    private static Path fixturePath() throws URISyntaxException {
        var resource = XxeDetectorTest.class.getClassLoader().getResource("fixtures/XxeFixture.java");
        if (resource == null) {
            throw new IllegalStateException("STEP 13 fixture not found");
        }
        return Path.of(resource.toURI());
    }

    private record Analysis(
            MethodInfo method,
            DataFlowResult dataFlow,
            List<ConfigurationFinding> findings) {}
}
