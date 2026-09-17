package com.totalsecurity.sast.detector.upload;

import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.VariableSymbol;
import com.totalsecurity.sast.dataflow.VariableSymbolKind;
import com.totalsecurity.sast.finding.FileUploadEvidence;
import com.totalsecurity.sast.finding.FileUploadEvidenceKind;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.expression.Expression;
import com.totalsecurity.sast.ir.expression.VariableReference;
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import com.totalsecurity.sast.rule.context.CallSiteContextResolver;
import com.totalsecurity.sast.rule.sink.SinkCategory;
import com.totalsecurity.sast.rule.sink.SinkMatch;
import com.totalsecurity.sast.rule.source.ParameterSourceMatch;
import com.totalsecurity.sast.rule.source.SpringMultipartOriginalFilenameSourceRule;
import com.totalsecurity.sast.rule.source.SpringMvcParameterSourceRule;
import com.totalsecurity.sast.rule.source.SourceMatch;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Proves direct external MultipartFile receiver identity and destination filename control. */
public final class SpringMultipartFileUploadAnalyzer {
    private static final Set<String> EXTERNAL_MULTIPART_RULES = Set.of(
            SpringMvcParameterSourceRule.REQUEST_PARAM_ID,
            SpringMvcParameterSourceRule.REQUEST_PART_ID);

    public List<SupportedFileUpload> analyze(
            JavaFileInfo file,
            ClassInfo enclosingClass,
            MethodInfo method,
            RuleAwareTaintResult analysis) {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(enclosingClass, "enclosingClass");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(analysis, "analysis");
        DataFlowResult dataFlow = analysis.taintResult().dataFlow();
        if (!dataFlow.graph().method().equals(method)) {
            throw new IllegalArgumentException("RuleAwareTaintResult belongs to a different method");
        }

        CallSiteContextResolver calls =
                new CallSiteContextResolver(file, enclosingClass, method, dataFlow);
        FileUploadTargetControlAnalysis controls =
                new FileUploadTargetControlAnalysis(analysis, calls);
        Map<SourceLocation, SupportedFileUpload> uploads = new LinkedHashMap<>();
        for (SinkMatch sink : analysis.sinkMatches()) {
            if (sink.category() != SinkCategory.FILE_UPLOAD_TARGET) {
                continue;
            }
            Optional<ParameterSourceMatch> multipartSource =
                    externalMultipartReceiver(sink, analysis, dataFlow, calls);
            if (multipartSource.isEmpty()) {
                continue;
            }
            Expression targetExpression = sink.call().call().arguments().getFirst();
            Optional<String> targetType = calls.qualifiedTypeOf(targetExpression)
                    .filter(type -> type.equals("java.nio.file.Path") || type.equals("java.io.File"));
            if (targetType.isEmpty()) {
                continue;
            }
            FileUploadTargetAssessment target = controls.classify(targetExpression);
            List<FileUploadEvidence> evidence = evidence(
                    sink, multipartSource.orElseThrow(), targetExpression, target, analysis);
            uploads.putIfAbsent(
                    sink.location(),
                    new SupportedFileUpload(
                            sink,
                            multipartSource.orElseThrow(),
                            targetType.orElseThrow(),
                            target,
                            evidence));
        }
        return List.copyOf(uploads.values());
    }

    private static Optional<ParameterSourceMatch> externalMultipartReceiver(
            SinkMatch sink,
            RuleAwareTaintResult analysis,
            DataFlowResult dataFlow,
            CallSiteContextResolver calls) {
        Expression receiver = sink.call().call().receiver().orElse(null);
        if (!(receiver instanceof VariableReference reference)) {
            return Optional.empty();
        }
        Optional<VariableSymbol> symbol = dataFlow.resolvedSymbol(reference)
                .filter(candidate -> candidate.kind() == VariableSymbolKind.PARAMETER)
                .filter(candidate -> calls.types().qualifyType(candidate.declaredType())
                        .filter(SpringMultipartOriginalFilenameSourceRule.MULTIPART_FILE::equals)
                        .isPresent());
        if (symbol.isEmpty()) {
            return Optional.empty();
        }
        SourceLocation declaration = symbol.orElseThrow().declarationLocation();
        return analysis.sourceMatches().stream()
                .filter(ParameterSourceMatch.class::isInstance)
                .map(ParameterSourceMatch.class::cast)
                .filter(source -> EXTERNAL_MULTIPART_RULES.contains(source.ruleId()))
                .filter(source -> source.location().equals(declaration))
                .findFirst();
    }

    private static List<FileUploadEvidence> evidence(
            SinkMatch sink,
            ParameterSourceMatch multipartSource,
            Expression targetExpression,
            FileUploadTargetAssessment target,
            RuleAwareTaintResult analysis) {
        LinkedHashSet<FileUploadEvidence> evidence = new LinkedHashSet<>();
        evidence.add(new FileUploadEvidence(
                FileUploadEvidenceKind.MULTIPART_SOURCE,
                multipartSource.evidence(),
                multipartSource.location()));
        target.origins().stream()
                .sorted(Comparator.comparing(com.totalsecurity.sast.taint.TaintSeed::id))
                .map(analysis::sourceMatch)
                .flatMap(Optional::stream)
                .map(SpringMultipartFileUploadAnalyzer::filenameEvidence)
                .forEach(evidence::add);
        evidence.addAll(target.constructionEvidence());
        if (target.constructionEvidence().isEmpty()) {
            evidence.add(new FileUploadEvidence(
                    FileUploadEvidenceKind.TARGET_CONSTRUCTION,
                    "Supported transfer target expression",
                    targetExpression.location()));
        }
        evidence.add(new FileUploadEvidence(
                FileUploadEvidenceKind.TRANSFER,
                sink.evidence(),
                sink.location()));
        List<FileUploadEvidence> ordered = new ArrayList<>(evidence);
        ordered.sort(Comparator
                .comparingInt((FileUploadEvidence item) -> item.location().startLine())
                .thenComparingInt(item -> item.location().startColumn())
                .thenComparing(item -> item.kind().ordinal()));
        return List.copyOf(ordered);
    }

    private static FileUploadEvidence filenameEvidence(SourceMatch source) {
        return new FileUploadEvidence(
                FileUploadEvidenceKind.FILENAME_SOURCE,
                source.evidence(),
                source.location());
    }
}
