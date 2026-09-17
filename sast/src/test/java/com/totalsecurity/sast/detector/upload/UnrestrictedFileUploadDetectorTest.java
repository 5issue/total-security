package com.totalsecurity.sast.detector.upload;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.cfg.ControlFlowGraph;
import com.totalsecurity.sast.cfg.ControlFlowGraphBuilder;
import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.ReachingDefinitionsAnalysis;
import com.totalsecurity.sast.finding.FileUploadEvidenceKind;
import com.totalsecurity.sast.finding.FileUploadFinding;
import com.totalsecurity.sast.finding.FindingSeverity;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.java.extractor.JavaSemanticExtractor;
import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import com.totalsecurity.sast.rule.RuleAwareTaintAnalysis;
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import com.totalsecurity.sast.rule.RuleRegistry;
import com.totalsecurity.sast.rule.sink.SinkCategory;
import com.totalsecurity.sast.rule.sink.SinkMatch;
import com.totalsecurity.sast.rule.sink.SpringMultipartFileTransferSinkRule;
import com.totalsecurity.sast.rule.source.SpringMultipartOriginalFilenameSourceRule;
import com.totalsecurity.sast.rule.source.SpringMvcParameterSourceRule;
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

class UnrestrictedFileUploadDetectorTest {
    private static final RuleRegistry RULES = RuleRegistry.javaSpringBackendDefaults();
    private static final UnrestrictedFileUploadDetector DETECTOR =
            new UnrestrictedFileUploadDetector();
    private static final SpringMultipartFileUploadAnalyzer ANALYZER =
            new SpringMultipartFileUploadAnalyzer();
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
                    .filter(candidate -> candidate.name().equals("UnrestrictedFileUploadFixture"))
                    .findFirst()
                    .orElseThrow();
            methods = type.methods().stream()
                    .collect(Collectors.toUnmodifiableMap(MethodInfo::name, Function.identity()));
        }
    }

    @ParameterizedTest
    @MethodSource("positiveFlows")
    void attackerControlledTrailingFilenameProducesFinding(String methodName) {
        Analysis analysis = analyze(methodName);
        assertEquals(1, analysis.findings().size());
        assertEquals(
                FileUploadTargetControl.ATTACKER_TYPE_CONTROLLED,
                only(analysis.uploads()).target().control());
    }

    private static Stream<String> positiveFlows() {
        return Stream.of(
                "requestParamPath",
                "requestPartPath",
                "directPath",
                "localAssignment",
                "fixedPrefix",
                "externalFilename",
                "attackerBranch",
                "multipleFilenameOrigins",
                "fileTarget",
                "fileSinglePathname",
                "fileParentChild",
                "nestedTrailingAttacker",
                "contentTypeDoesNotSanitize");
    }

    @ParameterizedTest
    @MethodSource("supportedTargets")
    void exactTransferToOverloadsUseUploadTargetCategory(
            String methodName, String targetType) {
        SinkMatch sink = only(uploadSinks(analyze(methodName).result()));
        assertEquals(SpringMultipartFileTransferSinkRule.ID, sink.ruleId());
        assertEquals(SinkCategory.FILE_UPLOAD_TARGET, sink.category());
        assertEquals("transferTo", sink.call().call().methodName());
        assertEquals(Set.of(0), sink.sensitiveArgumentIndexes());
        assertEquals(targetType, only(analyze(methodName).uploads()).targetType());
    }

    private static Stream<Arguments> supportedTargets() {
        return Stream.of(
                Arguments.of("directPath", "java.nio.file.Path"),
                Arguments.of("fileTarget", "java.io.File"));
    }

    @Test
    void requestPartIsAnExactSpringParameterSource() {
        Analysis analysis = analyze("requestPartPath");
        assertTrue(analysis.result().sourceMatches().stream()
                .anyMatch(source -> source.ruleId().equals(SpringMvcParameterSourceRule.REQUEST_PART_ID)));
        assertEquals(
                SpringMvcParameterSourceRule.REQUEST_PART_ID,
                only(analysis.uploads()).multipartSource().ruleId());
    }

    @Test
    void originalFilenameIsAnExactExpressionSource() {
        Analysis analysis = analyze("directPath");
        assertTrue(analysis.result().sourceMatches().stream()
                .anyMatch(source -> source.ruleId()
                        .equals(SpringMultipartOriginalFilenameSourceRule.ID)));
        assertTrue(only(analysis.uploads()).evidence().stream()
                .anyMatch(item -> item.kind() == FileUploadEvidenceKind.FILENAME_SOURCE
                        && item.detail().contains("getOriginalFilename")));
    }

    @ParameterizedTest
    @MethodSource("fixedExtensionFlows")
    void fixedTrailingExtensionIsNotConfirmed(String methodName) {
        Analysis analysis = analyze(methodName);
        assertEquals(
                FileUploadTargetControl.FIXED_EXTENSION,
                only(analysis.uploads()).target().control());
        assertTrue(analysis.findings().isEmpty());
    }

    private static Stream<String> fixedExtensionFlows() {
        return Stream.of(
                "originalWithFixedExtension",
                "inputWithFixedExtension",
                "splitFixedExtension",
                "generatedUuidWithFixedExtension",
                "fileTargetFixedExtension");
    }

    @Test
    void fixedServerFilenameIsClean() {
        Analysis analysis = analyze("fixedFilename");
        assertEquals(FileUploadTargetControl.CLEAN, only(analysis.uploads()).target().control());
        assertTrue(analysis.findings().isEmpty());
    }

    @ParameterizedTest
    @MethodSource("unknownTargetFlows")
    void unmodeledFilenameBuildersRemainUnknown(String methodName) {
        Analysis analysis = analyze(methodName);
        assertEquals(FileUploadTargetControl.UNKNOWN, only(analysis.uploads()).target().control());
        assertTrue(analysis.findings().isEmpty());
    }

    private static Stream<String> unknownTargetFlows() {
        return Stream.of("customOriginalFilename", "unknownBuilder", "validationNameIsNotAProof");
    }

    @ParameterizedTest
    @MethodSource("excludedFlows")
    void missingExactSourceReceiverOrTransferProducesNoFinding(String methodName) {
        Analysis analysis = analyze(methodName);
        assertTrue(analysis.findings().isEmpty());
    }

    private static Stream<String> excludedFlows() {
        return Stream.of(
                "sourceWithoutTransfer",
                "nonExternalMultipart",
                "customMultipart",
                "customTransfer",
                "contentTypeOnly",
                "customRequestPart",
                "ordinaryFilesWrite",
                "pathTraversalOnly",
                "originalFilenameReadOnly",
                "targetOnly");
    }

    @Test
    void customMultipartAndCustomTransferDoNotCreateUploadSinkMatches() {
        assertTrue(uploadSinks(analyze("customMultipart").result()).isEmpty());
        assertTrue(uploadSinks(analyze("customTransfer").result()).isEmpty());
    }

    @Test
    void customOriginalFilenameIsNotAnExternalFilenameSource() {
        Analysis analysis = analyze("customOriginalFilename");
        assertFalse(analysis.result().sourceMatches().stream()
                .anyMatch(source -> source.ruleId().equals(SpringMultipartOriginalFilenameSourceRule.ID)));
        assertTrue(analysis.findings().isEmpty());
    }

    @Test
    void customRequestPartSimpleNameDoesNotEstablishExternalReceiver() {
        Analysis analysis = analyze("customRequestPart");
        assertFalse(analysis.result().sourceMatches().stream()
                .anyMatch(source -> source.ruleId().equals(SpringMvcParameterSourceRule.REQUEST_PART_ID)));
        assertTrue(analysis.uploads().isEmpty());
    }

    @Test
    void getContentTypeIsNeitherSafetyProofNorRequiredForFinding() {
        assertTrue(analyze("contentTypeOnly").findings().isEmpty());
        assertEquals(1, analyze("contentTypeDoesNotSanitize").findings().size());
    }

    @Test
    void multipleFilenameOriginsProduceOnePhysicalFindingAndRetainEvidence() {
        Analysis analysis = analyze("multipleFilenameOrigins");
        FileUploadFinding finding = only(analysis.findings());
        assertEquals(1, analysis.findings().size());
        assertEquals(
                2,
                finding.contextEvidence().stream()
                        .filter(item -> item.kind() == FileUploadEvidenceKind.FILENAME_SOURCE)
                        .count());
    }

    @Test
    void findingMetadataAndStructuredEvidenceAreConservative() {
        FileUploadFinding finding = only(analyze("requestParamPath").findings());
        assertEquals(UnrestrictedFileUploadDetector.RULE_ID, finding.ruleId());
        assertEquals("Unrestricted File Upload", finding.vulnerabilityType());
        assertEquals("CWE-434", finding.cwe());
        assertEquals(FindingSeverity.HIGH, finding.severity());
        assertEquals(SinkCategory.FILE_UPLOAD_TARGET, finding.sink().category());
        assertEquals("java.nio.file.Path", finding.targetType());
        assertEquals(
                Set.of(
                        FileUploadEvidenceKind.MULTIPART_SOURCE,
                        FileUploadEvidenceKind.FILENAME_SOURCE,
                        FileUploadEvidenceKind.TARGET_CONSTRUCTION,
                        FileUploadEvidenceKind.TRANSFER),
                finding.contextEvidence().stream()
                        .map(item -> item.kind())
                        .collect(Collectors.toSet()));
        assertTrue(finding.evidence().contains("attacker-controlled filename/type"));
        assertFalse(finding.evidence().contains("executable"));
        assertFalse(finding.evidence().contains("guaranteed"));
    }

    @ParameterizedTest
    @MethodSource("controlMerges")
    void controlLatticeUsesMayAnalysis(
            FileUploadTargetControl left,
            FileUploadTargetControl right,
            FileUploadTargetControl expected) {
        assertEquals(expected, left.join(right));
        assertEquals(expected, right.join(left));
    }

    private static Stream<Arguments> controlMerges() {
        return Stream.of(
                Arguments.of(
                        FileUploadTargetControl.CLEAN,
                        FileUploadTargetControl.CLEAN,
                        FileUploadTargetControl.CLEAN),
                Arguments.of(
                        FileUploadTargetControl.CLEAN,
                        FileUploadTargetControl.FIXED_EXTENSION,
                        FileUploadTargetControl.FIXED_EXTENSION),
                Arguments.of(
                        FileUploadTargetControl.UNKNOWN,
                        FileUploadTargetControl.FIXED_EXTENSION,
                        FileUploadTargetControl.UNKNOWN),
                Arguments.of(
                        FileUploadTargetControl.ATTACKER_TYPE_CONTROLLED,
                        FileUploadTargetControl.CLEAN,
                        FileUploadTargetControl.ATTACKER_TYPE_CONTROLLED),
                Arguments.of(
                        FileUploadTargetControl.ATTACKER_TYPE_CONTROLLED,
                        FileUploadTargetControl.UNKNOWN,
                        FileUploadTargetControl.ATTACKER_TYPE_CONTROLLED));
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

    private static List<SinkMatch> uploadSinks(RuleAwareTaintResult result) {
        return result.sinkMatches().stream()
                .filter(sink -> sink.category() == SinkCategory.FILE_UPLOAD_TARGET)
                .toList();
    }

    private static <T> T only(List<T> values) {
        assertEquals(1, values.size());
        return values.getFirst();
    }

    private static Path fixturePath() throws URISyntaxException {
        var resource = UnrestrictedFileUploadDetectorTest.class
                .getClassLoader()
                .getResource("fixtures/UnrestrictedFileUploadFixture.java");
        if (resource == null) {
            throw new IllegalStateException("STEP 17 fixture not found");
        }
        return Path.of(resource.toURI());
    }

    private record Analysis(
            RuleAwareTaintResult result,
            List<SupportedFileUpload> uploads,
            List<FileUploadFinding> findings) {}
}
