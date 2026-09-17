package com.totalsecurity.sast.detector.deserialization;

import com.totalsecurity.sast.dataflow.Definition;
import com.totalsecurity.sast.dataflow.UseSite;
import com.totalsecurity.sast.finding.DeserializationEvidence;
import com.totalsecurity.sast.finding.DeserializationFinding;
import com.totalsecurity.sast.finding.FindingFlow;
import com.totalsecurity.sast.finding.FindingFlowStep;
import com.totalsecurity.sast.finding.FindingFlowStepKind;
import com.totalsecurity.sast.finding.FindingSeverity;
import com.totalsecurity.sast.finding.FindingSource;
import com.totalsecurity.sast.finding.FindingSourceKind;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
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
import com.totalsecurity.sast.rule.source.ExpressionSourceMatch;
import com.totalsecurity.sast.rule.source.ParameterSourceMatch;
import com.totalsecurity.sast.rule.source.SourceMatch;
import com.totalsecurity.sast.taint.TaintSeed;
import com.totalsecurity.sast.taint.TaintState;
import com.totalsecurity.sast.taint.TaintTrace;
import com.totalsecurity.sast.taint.TaintTraceEdge;
import com.totalsecurity.sast.taint.TaintTraceStep;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** CWE-502 detector for source-backed, same-method Java ObjectInputStream.readObject uses. */
public final class InsecureDeserializationDetector {
    public static final String RULE_ID = "INSECURE_DESERIALIZATION";
    public static final String VULNERABILITY_TYPE = "Insecure Deserialization";
    public static final String CWE = "CWE-502";
    public static final FindingSeverity SEVERITY = FindingSeverity.HIGH;
    public static final String EVIDENCE =
            "Supported external input reaches Java native object deserialization.";

    private final JavaObjectDeserializationAnalyzer analyzer =
            new JavaObjectDeserializationAnalyzer();

    public List<DeserializationFinding> detect(
            JavaFileInfo file,
            ClassInfo enclosingClass,
            MethodInfo method,
            RuleAwareTaintResult analysis) {
        return analyzer.analyze(file, enclosingClass, method, analysis).stream()
                .filter(use -> use.inputState() == TaintState.TAINTED)
                .map(use -> toFinding(analysis, use))
                .toList();
    }

    private static DeserializationFinding toFinding(
            RuleAwareTaintResult analysis, NativeDeserializationUse use) {
        LinkedHashMap<String, FindingSource> sources = new LinkedHashMap<>();
        LinkedHashMap<String, FindingFlow> flows = new LinkedHashMap<>();
        LinkedHashSet<DeserializationEvidence> evidence = new LinkedHashSet<>();
        LinkedHashSet<com.totalsecurity.sast.ir.SourceLocation> creationLocations =
                new LinkedHashSet<>();

        use.lineages().stream()
                .filter(lineage -> lineage.inputTaint().state() == TaintState.TAINTED)
                .sorted(Comparator.comparingInt(lineage ->
                        lineage.objectInputStreamCreationLocation().startLine()))
                .forEach(lineage -> {
                    evidence.addAll(lineage.evidence());
                    creationLocations.add(lineage.objectInputStreamCreationLocation());
                    addSourceFlows(analysis, use, lineage, sources, flows);
                });
        evidence.add(new DeserializationEvidence(
                JavaObjectDeserializationAnalyzer.OBJECT_INPUT_STREAM + ".readObject()",
                "Java native deserialization use",
                use.readObjectLocation()));

        if (sources.isEmpty()) {
            throw new IllegalStateException("Confirmed deserialization use has no source origin");
        }
        return new DeserializationFinding(
                RULE_ID,
                VULNERABILITY_TYPE,
                CWE,
                SEVERITY,
                use.readObjectLocation(),
                List.copyOf(sources.values()),
                List.copyOf(flows.values()),
                JavaObjectDeserializationAnalyzer.OBJECT_INPUT_STREAM,
                List.copyOf(evidence),
                creationLocations.stream()
                        .sorted(Comparator.comparingInt(location -> location.startLine()))
                        .toList(),
                use.readObjectLocation(),
                EVIDENCE);
    }

    private static void addSourceFlows(
            RuleAwareTaintResult analysis,
            NativeDeserializationUse use,
            DeserializationLineage lineage,
            Map<String, FindingSource> sources,
            Map<String, FindingFlow> flows) {
        TaintTrace trace = analysis.taintResult().traceTo(lineage.taintEndpoint());
        lineage.inputTaint().origins().stream()
                .sorted(Comparator.comparing(TaintSeed::id))
                .forEach(origin -> {
                    SourceMatch match = analysis.sourceMatch(origin).orElseThrow(() ->
                            new IllegalStateException(
                                    "Taint origin has no SourceMatch: " + origin.id()));
                    FindingSource source = toSource(match, origin);
                    sources.putIfAbsent(origin.id(), source);
                    flows.putIfAbsent(
                            origin.id(),
                            new FindingFlow(source, toFlowSteps(trace, origin, source, lineage, use)));
                });
    }

    private static FindingSource toSource(SourceMatch match, TaintSeed seed) {
        return switch (match) {
            case ParameterSourceMatch parameter -> new FindingSource(
                    parameter.ruleId(),
                    seed.id(),
                    FindingSourceKind.PARAMETER,
                    parameter.location(),
                    "External parameter " + parameter.parameter().name(),
                    parameter.evidence());
            case ExpressionSourceMatch expression -> new FindingSource(
                    expression.ruleId(),
                    seed.id(),
                    FindingSourceKind.EXPRESSION,
                    expression.location(),
                    "External return value of " + expression.expression().call().methodName(),
                    expression.evidence());
        };
    }

    private static List<FindingFlowStep> toFlowSteps(
            TaintTrace trace,
            TaintSeed origin,
            FindingSource source,
            DeserializationLineage lineage,
            NativeDeserializationUse use) {
        TaintTraceStep sourceStep = trace.steps().stream()
                .filter(step -> step.seed().filter(origin::equals).isPresent())
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "Provenance trace does not contain source " + origin.id()));
        List<FindingFlowStep> steps = new ArrayList<>();
        for (TaintTraceStep step : shortestPath(trace, sourceStep)) {
            steps.add(toFlowStep(step, source));
        }
        for (DeserializationEvidence entry : lineage.evidence()) {
            steps.add(new FindingFlowStep(
                    FindingFlowStepKind.EXPRESSION, entry.location(), entry.detail()));
        }
        steps.add(new FindingFlowStep(
                FindingFlowStepKind.SINK,
                use.readObjectLocation(),
                "Java native deserialization ObjectInputStream.readObject"));
        return List.copyOf(steps);
    }

    private static List<TaintTraceStep> shortestPath(
            TaintTrace trace, TaintTraceStep source) {
        Map<TaintTraceStep, List<TaintTraceStep>> outgoing = new HashMap<>();
        for (TaintTraceEdge edge : trace.edges()) {
            outgoing.computeIfAbsent(edge.source(), ignored -> new ArrayList<>())
                    .add(edge.target());
        }
        outgoing.values().forEach(targets ->
                targets.sort(Comparator.comparingInt(TaintTraceStep::id)));
        ArrayDeque<TaintTraceStep> work = new ArrayDeque<>();
        Set<TaintTraceStep> visited = new LinkedHashSet<>();
        Map<TaintTraceStep, TaintTraceStep> predecessor = new HashMap<>();
        work.add(source);
        visited.add(source);
        while (!work.isEmpty()) {
            TaintTraceStep current = work.removeFirst();
            if (current.equals(trace.target())) {
                return rebuildPath(source, trace.target(), predecessor);
            }
            for (TaintTraceStep next : outgoing.getOrDefault(current, List.of())) {
                if (visited.add(next)) {
                    predecessor.put(next, current);
                    work.addLast(next);
                }
            }
        }
        throw new IllegalStateException("No provenance path from source to deserialization input");
    }

    private static List<TaintTraceStep> rebuildPath(
            TaintTraceStep source,
            TaintTraceStep target,
            Map<TaintTraceStep, TaintTraceStep> predecessor) {
        ArrayList<TaintTraceStep> reversed = new ArrayList<>();
        TaintTraceStep current = target;
        reversed.add(current);
        while (!current.equals(source)) {
            current = Objects.requireNonNull(
                    predecessor.get(current), "Incomplete provenance predecessor chain");
            reversed.add(current);
        }
        java.util.Collections.reverse(reversed);
        return List.copyOf(reversed);
    }

    private static FindingFlowStep toFlowStep(
            TaintTraceStep step, FindingSource source) {
        return switch (step.kind()) {
            case SEED -> new FindingFlowStep(
                    FindingFlowStepKind.SOURCE, source.location(), source.summary());
            case DEFINITION -> definitionStep(step.definition().orElseThrow());
            case USE -> useStep(step.useSite().orElseThrow());
            case EXPRESSION -> expressionStep(step.expression().orElseThrow());
        };
    }

    private static FindingFlowStep definitionStep(Definition definition) {
        return new FindingFlowStep(
                FindingFlowStepKind.DEFINITION,
                definition.location(),
                "Definition of " + definition.variable().name() + " (" + definition.kind() + ")");
    }

    private static FindingFlowStep useStep(UseSite use) {
        return new FindingFlowStep(
                FindingFlowStepKind.USE,
                use.reference().location(),
                "Use of " + use.variable().name());
    }

    private static FindingFlowStep expressionStep(Expression expression) {
        return new FindingFlowStep(
                FindingFlowStepKind.EXPRESSION,
                expression.location(),
                switch (expression) {
                    case VariableReference reference -> "Variable reference " + reference.name();
                    case Literal literal -> "Literal " + literal.kind();
                    case BinaryExpression binary -> "Binary expression " + binary.operator();
                    case AssignmentExpression assignment ->
                            "Assignment expression " + assignment.assignment().operator();
                    case MethodCallExpression call ->
                            "Return value of " + call.call().methodName();
                    case ObjectCreationExpression creation ->
                            "Object creation " + creation.typeName();
                    case FieldAccessExpression field -> "Field access " + field.fieldName();
                    case ParenthesizedExpression ignored -> "Parenthesized expression";
                    case UnknownExpression unknown ->
                            "Unsupported expression " + unknown.syntaxKind();
                });
    }
}
