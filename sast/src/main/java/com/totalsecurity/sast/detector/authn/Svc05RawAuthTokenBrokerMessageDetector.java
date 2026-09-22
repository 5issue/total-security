package com.totalsecurity.sast.detector.authn;

import com.totalsecurity.sast.finding.ChecklistFlowFinding;
import com.totalsecurity.sast.finding.FindingFlow;
import com.totalsecurity.sast.finding.FindingFlowStep;
import com.totalsecurity.sast.finding.FindingFlowStepKind;
import com.totalsecurity.sast.finding.FindingSeverity;
import com.totalsecurity.sast.finding.FindingSink;
import com.totalsecurity.sast.finding.FindingSource;
import com.totalsecurity.sast.finding.FindingSourceKind;
import com.totalsecurity.sast.interprocedural.CrossClassInterproceduralAnalysis;
import com.totalsecurity.sast.interprocedural.CrossClassInterproceduralResult;
import com.totalsecurity.sast.interprocedural.ProjectCallResolution;
import com.totalsecurity.sast.interprocedural.ProjectClassEntry;
import com.totalsecurity.sast.interprocedural.ProjectMethodId;
import com.totalsecurity.sast.interprocedural.SameClassMethodSummary;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.expression.AssignmentExpression;
import com.totalsecurity.sast.ir.expression.BinaryExpression;
import com.totalsecurity.sast.ir.expression.Expression;
import com.totalsecurity.sast.ir.expression.FieldAccessExpression;
import com.totalsecurity.sast.ir.expression.Literal;
import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import com.totalsecurity.sast.ir.expression.ObjectCreationExpression;
import com.totalsecurity.sast.ir.expression.ParenthesizedExpression;
import com.totalsecurity.sast.ir.expression.UnknownExpression;
import com.totalsecurity.sast.ir.expression.VariableReference;
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import com.totalsecurity.sast.rule.RuleRegistry;
import com.totalsecurity.sast.rule.context.CallSiteContextResolver;
import com.totalsecurity.sast.rule.context.LombokGetterNamingContext;
import com.totalsecurity.sast.rule.sink.SinkCategory;
import com.totalsecurity.sast.rule.sink.SinkMatch;
import com.totalsecurity.sast.rule.sink.SpringRabbitTemplateMessageSinkRule;
import com.totalsecurity.sast.rule.source.ExpressionSourceMatch;
import com.totalsecurity.sast.rule.source.ParameterSourceMatch;
import com.totalsecurity.sast.rule.source.SourceMatch;
import com.totalsecurity.sast.taint.TaintAnalysisResult;
import com.totalsecurity.sast.taint.TaintSeed;
import com.totalsecurity.sast.taint.TaintState;
import com.totalsecurity.sast.taint.TaintTrace;
import com.totalsecurity.sast.taint.TaintTraceEdge;
import com.totalsecurity.sast.taint.TaintTraceStep;
import com.totalsecurity.sast.taint.model.MethodTaintModel;
import com.totalsecurity.sast.taint.model.RecordAccessorMethodTaintModel;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** SVC-05 analysis for source-proven raw authentication tokens in RabbitMQ payloads. */
public final class Svc05RawAuthTokenBrokerMessageDetector {
    public static final String RULE_ID = "SVC_05_RAW_AUTH_TOKEN_BROKER_MESSAGE";
    public static final String CHECKLIST_ID = "SVC-05";
    public static final String VULNERABILITY_TYPE = "Raw Authentication Token in Broker Message";
    public static final FindingSeverity SEVERITY = FindingSeverity.HIGH;

    public Svc05AnalysisResult analyze(Collection<JavaFileInfo> files) {
        return analyze(files, LombokGetterNamingContext.unknown());
    }

    public Svc05AnalysisResult analyze(
            Collection<JavaFileInfo> files, LombokGetterNamingContext lombokNaming) {
        Objects.requireNonNull(files, "files");
        Objects.requireNonNull(lombokNaming, "lombokNaming");
        com.totalsecurity.sast.interprocedural.ProjectClassIndex projectTypes =
                new com.totalsecurity.sast.interprocedural.ProjectClassIndex(files);
        SpringRabbitTemplateMessageSinkRule rabbitSink =
                new SpringRabbitTemplateMessageSinkRule(projectTypes);
        CrossClassInterproceduralResult project = new CrossClassInterproceduralAnalysis()
                .analyze(files, policyRules(files, rabbitSink), lombokNaming);
        LinkedHashMap<FindingKey, FindingAccumulator> findings = new LinkedHashMap<>();
        LinkedHashSet<UnsupportedSvc05Flow> unsupported = new LinkedHashSet<>();
        Svc05PayloadInspector payloadInspector = new Svc05PayloadInspector();

        for (Map.Entry<ProjectMethodId, RuleAwareTaintResult> item
                : project.methodAnalyses().entrySet()) {
            ProjectMethodId methodId = item.getKey();
            ProjectClassEntry owner = project.classIndex()
                    .uniqueClass(methodId.ownerQualifiedName()).orElse(null);
            if (owner == null) {
                continue;
            }
            RuleAwareTaintResult analysis = item.getValue();
            CallSiteContextResolver calls = new CallSiteContextResolver(
                    owner.file(), owner.type(), methodId.method(),
                    analysis.taintResult().dataFlow(), project.classIndex(), lombokNaming);
            calls.callSites().forEach(call -> {
                var classification = rabbitSink.classify(call);
                if (classification.status()
                        == SpringRabbitTemplateMessageSinkRule.ClassificationStatus.UNSUPPORTED) {
                    unsupported.add(new UnsupportedSvc05Flow(
                            classification.reason(), call.location()));
                }
            });
            for (SinkMatch sink : analysis.sinkMatches()) {
                if (sink.category() != SinkCategory.ASYNC_MESSAGE_PUBLISH) {
                    continue;
                }
                int payloadIndex = sink.sensitiveArgumentIndexes().iterator().next();
                Expression payload = sink.call().call().arguments().get(payloadIndex);
                Svc05PayloadInspector.PayloadInspection inspection = payloadInspector.inspect(
                        payload, calls, analysis.taintResult().dataFlow(),
                        analysis.taintResult(), project.classIndex());
                unsupported.addAll(inspection.unsupported());
                for (Expression value : inspection.values()) {
                    var taintValue = analysis.taintResult().taintOf(value);
                    if (taintValue.state() == TaintState.UNKNOWN) {
                        unsupported.add(new UnsupportedSvc05Flow(
                                "Broker payload value taint is UNKNOWN", value.location()));
                        continue;
                    }
                    if (taintValue.state() != TaintState.TAINTED) {
                        continue;
                    }
                    for (TaintSeed origin : taintValue.origins()) {
                        analysis.sourceMatch(origin).ifPresent(source -> findings
                                .computeIfAbsent(
                                        new FindingKey(RULE_ID, sink.location(), payloadIndex),
                                        ignored -> new FindingAccumulator(sink, payloadIndex))
                                .add(new RawFlow(value, origin, source, methodId, analysis)));
                    }
                }
            }
        }

        List<ChecklistFlowFinding> result = findings.values().stream()
                .map(accumulator -> accumulator.toFinding(project))
                .sorted(Comparator.comparing((ChecklistFlowFinding finding) ->
                                finding.primaryLocation().file().toString())
                        .thenComparingInt(finding -> finding.primaryLocation().startLine())
                        .thenComparingInt(finding -> finding.primaryLocation().startColumn()))
                .toList();
        return new Svc05AnalysisResult(
                result,
                unsupported.stream()
                        .sorted(Comparator.comparing((UnsupportedSvc05Flow item) ->
                                        item.location().file().toString())
                                .thenComparingInt(item -> item.location().startLine())
                                .thenComparing(UnsupportedSvc05Flow::reason))
                        .toList());
    }

    private static RuleRegistry policyRules(
            Collection<JavaFileInfo> files,
            SpringRabbitTemplateMessageSinkRule rabbitSink) {
        RuleRegistry defaults = RuleRegistry.javaSpringBackendDefaults();
        Svc05IssuerDiscovery.IssuerTypes issuers =
                new Svc05IssuerDiscovery().discover(files);
        List<MethodTaintModel> models = new ArrayList<>(defaults.methodModels().stream()
                .filter(model -> !model.id().equals(RecordAccessorMethodTaintModel.ID))
                .toList());
        models.add(new Svc05RecordAccessorMethodTaintModel(issuers.issuedTokenRecords()));
        models.add(new Svc05ReversibleEncodingMethodTaintModel());
        return new RuleRegistry(
                List.of(new Svc05RawAuthTokenSourceRule(issuers)),
                List.of(rabbitSink),
                List.of(new RefreshTokenHashSanitizerRule(
                        new CryptographicRefreshTokenHasherDiscovery().discover(files))),
                models);
    }

    private static FindingSource source(SourceMatch match, TaintSeed seed) {
        return switch (match) {
            case ParameterSourceMatch parameter -> new FindingSource(
                    parameter.ruleId(), seed.id(), FindingSourceKind.PARAMETER,
                    parameter.location(),
                    "Raw authentication-token parameter " + parameter.parameter().name(),
                    parameter.evidence());
            case ExpressionSourceMatch expression -> new FindingSource(
                    expression.ruleId(), seed.id(), FindingSourceKind.EXPRESSION,
                    expression.location(), "Source-proven authentication-token expression",
                    expression.evidence());
        };
    }

    private static List<FindingFlowStep> flowTo(
            TaintAnalysisResult taint,
            Expression endpoint,
            TaintSeed seed,
            FindingSource source) {
        TaintTrace trace = taint.traceTo(endpoint);
        TaintTraceStep sourceStep = trace.steps().stream()
                .filter(step -> step.seed().filter(seed::equals).isPresent())
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "SVC-05 trace lacks source origin " + seed.id()));
        List<FindingFlowStep> result = new ArrayList<>();
        for (TaintTraceStep step : shortestPath(trace, sourceStep)) {
            result.add(toFlowStep(step, source));
        }
        return List.copyOf(result);
    }

    private static List<TaintTraceStep> shortestPath(
            TaintTrace trace, TaintTraceStep source) {
        Map<TaintTraceStep, List<TaintTraceStep>> outgoing = new HashMap<>();
        for (TaintTraceEdge edge : trace.edges()) {
            outgoing.computeIfAbsent(edge.source(), ignored -> new ArrayList<>())
                    .add(edge.target());
        }
        outgoing.values().forEach(values ->
                values.sort(Comparator.comparingInt(TaintTraceStep::id)));
        ArrayDeque<TaintTraceStep> work = new ArrayDeque<>();
        Set<TaintTraceStep> visited = new LinkedHashSet<>();
        Map<TaintTraceStep, TaintTraceStep> predecessor = new HashMap<>();
        work.add(source);
        visited.add(source);
        while (!work.isEmpty()) {
            TaintTraceStep current = work.removeFirst();
            if (current.equals(trace.target())) {
                ArrayList<TaintTraceStep> reversed = new ArrayList<>();
                reversed.add(current);
                while (!current.equals(source)) {
                    current = Objects.requireNonNull(predecessor.get(current));
                    reversed.add(current);
                }
                java.util.Collections.reverse(reversed);
                return reversed;
            }
            for (TaintTraceStep next : outgoing.getOrDefault(current, List.of())) {
                if (visited.add(next)) {
                    predecessor.put(next, current);
                    work.addLast(next);
                }
            }
        }
        throw new IllegalStateException("No SVC-05 provenance path to broker payload");
    }

    private static FindingFlowStep toFlowStep(
            TaintTraceStep step, FindingSource source) {
        return switch (step.kind()) {
            case SEED -> new FindingFlowStep(
                    FindingFlowStepKind.SOURCE, source.location(), source.summary());
            case DEFINITION -> new FindingFlowStep(
                    FindingFlowStepKind.DEFINITION,
                    step.definition().orElseThrow().location(),
                    "Definition of " + step.definition().orElseThrow().variable().name());
            case USE -> new FindingFlowStep(
                    FindingFlowStepKind.USE,
                    step.useSite().orElseThrow().reference().location(),
                    "Use of " + step.useSite().orElseThrow().variable().name());
            case EXPRESSION -> new FindingFlowStep(
                    FindingFlowStepKind.EXPRESSION,
                    step.expression().orElseThrow().location(),
                    expressionSummary(step.expression().orElseThrow()));
        };
    }

    private static String expressionSummary(Expression expression) {
        return switch (expression) {
            case VariableReference reference -> "Variable reference " + reference.name();
            case Literal literal -> "Literal " + literal.kind();
            case BinaryExpression binary -> "Binary expression " + binary.operator();
            case AssignmentExpression assignment ->
                    "Assignment expression " + assignment.assignment().operator();
            case MethodCallExpression call -> "Return value of " + call.call().methodName();
            case ObjectCreationExpression creation -> "Object creation " + creation.typeName();
            case FieldAccessExpression field -> "Field access " + field.fieldName();
            case ParenthesizedExpression ignored -> "Parenthesized expression";
            case UnknownExpression unknown -> "Unsupported expression " + unknown.syntaxKind();
        };
    }

    private static List<FindingFlowStep> expandReturnBoundaries(
            List<FindingFlowStep> original,
            RawFlow raw,
            CrossClassInterproceduralResult project) {
        List<ProjectCallResolution> calls = project.callResolutions().stream()
                .filter(item -> item.caller().equals(raw.method()))
                .filter(item -> item.target().isPresent())
                .toList();
        if (calls.isEmpty()) {
            return List.copyOf(original);
        }
        List<FindingFlowStep> expanded = new ArrayList<>();
        for (FindingFlowStep step : original) {
            ProjectCallResolution boundary = calls.stream()
                    .filter(item -> item.call().location().equals(step.location()))
                    .findFirst().orElse(null);
            if (boundary != null && step.kind() == FindingFlowStepKind.EXPRESSION) {
                ProjectMethodId target = boundary.target().orElseThrow();
                SameClassMethodSummary summary = project.methodSummaries().get(target);
                if (summary != null) {
                    int parameterIndex = matchingParameterIndex(
                            raw.analysis().taintResult(), boundary.call(), raw.seed(),
                            summary.returnDependency().parameterIndexes());
                    if (parameterIndex >= 0) {
                        expanded.add(new FindingFlowStep(
                                FindingFlowStepKind.METHOD_CALL,
                                boundary.call().location(),
                                "Project call " + raw.method().boundaryName()
                                        + " -> " + target.boundaryName()));
                        expanded.add(new FindingFlowStep(
                                FindingFlowStepKind.PARAMETER_BINDING,
                                target.method().parameters().get(parameterIndex).location(),
                                "Bind argument " + parameterIndex + " to "
                                        + target.boundaryName() + " parameter "
                                        + target.method().parameters().get(parameterIndex).name()));
                        expanded.addAll(summary.returnDependency().parameterFlows()
                                .getOrDefault(parameterIndex, List.of()));
                        expanded.add(new FindingFlowStep(
                                FindingFlowStepKind.METHOD_RETURN,
                                boundary.call().location(),
                                "Return from " + target.boundaryName()));
                    }
                }
            }
            expanded.add(step);
        }
        return List.copyOf(expanded);
    }

    private static int matchingParameterIndex(
            TaintAnalysisResult taint,
            MethodCallExpression call,
            TaintSeed origin,
            Set<Integer> indexes) {
        return indexes.stream().sorted()
                .filter(index -> taint.argumentTaint(call, index).origins().contains(origin))
                .findFirst().orElse(-1);
    }

    private static final class FindingAccumulator {
        private final SinkMatch sink;
        private final int payloadIndex;
        private final List<RawFlow> rawFlows = new ArrayList<>();

        private FindingAccumulator(SinkMatch sink, int payloadIndex) {
            this.sink = sink;
            this.payloadIndex = payloadIndex;
        }

        private void add(RawFlow flow) {
            rawFlows.add(flow);
        }

        private ChecklistFlowFinding toFinding(CrossClassInterproceduralResult project) {
            LinkedHashMap<String, FindingSource> sources = new LinkedHashMap<>();
            LinkedHashSet<FindingFlow> flows = new LinkedHashSet<>();
            for (RawFlow raw : rawFlows) {
                FindingSource source = source(raw.source(), raw.seed());
                sources.putIfAbsent(source.seedId(), source);
                List<FindingFlowStep> steps = new ArrayList<>(expandReturnBoundaries(
                        flowTo(raw.analysis().taintResult(), raw.payload(), raw.seed(), source),
                        raw,
                        project));
                steps.add(new FindingFlowStep(
                        FindingFlowStepKind.SINK,
                        sink.location(),
                        "Raw authentication-token value reaches exact RabbitTemplate payload argument "
                                + payloadIndex));
                flows.add(new FindingFlow(source, steps));
            }
            FindingSink findingSink = new FindingSink(
                    sink.ruleId(),
                    SinkCategory.ASYNC_MESSAGE_PUBLISH,
                    sink.call().call().methodName(),
                    payloadIndex,
                    sink.location());
            return new ChecklistFlowFinding(
                    RULE_ID,
                    CHECKLIST_ID,
                    VULNERABILITY_TYPE,
                    SEVERITY,
                    sink.location(),
                    List.copyOf(sources.values()),
                    findingSink,
                    List.copyOf(flows),
                    CHECKLIST_ID + ": source-proven raw authentication token reaches an exact "
                            + "RabbitMQ message payload (token value redacted)");
        }
    }

    private record RawFlow(
            Expression payload,
            TaintSeed seed,
            SourceMatch source,
            ProjectMethodId method,
            RuleAwareTaintResult analysis) {}

    private record FindingKey(String ruleId, SourceLocation location, int argumentIndex) {}
}
