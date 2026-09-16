package com.totalsecurity.sast.detector.sql;

import com.totalsecurity.sast.dataflow.Definition;
import com.totalsecurity.sast.dataflow.UseSite;
import com.totalsecurity.sast.detector.VulnerabilityDetector;
import com.totalsecurity.sast.finding.Finding;
import com.totalsecurity.sast.finding.FindingFlow;
import com.totalsecurity.sast.finding.FindingFlowStep;
import com.totalsecurity.sast.finding.FindingFlowStepKind;
import com.totalsecurity.sast.finding.FindingSeverity;
import com.totalsecurity.sast.finding.FindingSink;
import com.totalsecurity.sast.finding.FindingSource;
import com.totalsecurity.sast.finding.FindingSourceKind;
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
import com.totalsecurity.sast.rule.sink.SinkCategory;
import com.totalsecurity.sast.rule.sink.SinkMatch;
import com.totalsecurity.sast.rule.source.ExpressionSourceMatch;
import com.totalsecurity.sast.rule.source.ParameterSourceMatch;
import com.totalsecurity.sast.rule.source.SourceMatch;
import com.totalsecurity.sast.taint.TaintSeed;
import com.totalsecurity.sast.taint.TaintState;
import com.totalsecurity.sast.taint.TaintTrace;
import com.totalsecurity.sast.taint.TaintTraceEdge;
import com.totalsecurity.sast.taint.TaintTraceStep;
import com.totalsecurity.sast.taint.TaintValue;
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

/** CWE-89 detector over STEP 6 SQL_TEXT sink matches and STEP 5 taint provenance. */
public final class SqlInjectionDetector implements VulnerabilityDetector {
    public static final String RULE_ID = "SQL_INJECTION";
    public static final String VULNERABILITY_TYPE = "SQL Injection";
    public static final String CWE = "CWE-89";
    public static final FindingSeverity SEVERITY = FindingSeverity.HIGH;

    @Override
    public List<Finding> detect(RuleAwareTaintResult analysis) {
        Objects.requireNonNull(analysis, "analysis");
        LinkedHashMap<PhysicalSinkKey, List<SinkArgument>> candidates = new LinkedHashMap<>();
        for (SinkMatch sink : analysis.sinkMatches()) {
            if (sink.category() != SinkCategory.SQL_TEXT) {
                continue;
            }
            for (int argumentIndex : sink.sensitiveArgumentIndexes()) {
                PhysicalSinkKey key = new PhysicalSinkKey(sink.call().location(), argumentIndex);
                candidates.computeIfAbsent(key, ignored -> new ArrayList<>())
                        .add(new SinkArgument(sink, argumentIndex));
            }
        }

        List<Finding> findings = new ArrayList<>();
        for (List<SinkArgument> matches : candidates.values()) {
            SinkArgument candidate = matches.stream()
                    .min(Comparator.comparing(item -> item.sink().ruleId()))
                    .orElseThrow();
            TaintValue taint = analysis.sinkArgumentTaint(candidate.sink(), candidate.argumentIndex());
            if (taint.state() != TaintState.TAINTED) {
                continue;
            }
            findings.add(toFinding(analysis, candidate, taint));
        }
        return List.copyOf(findings);
    }

    private Finding toFinding(
            RuleAwareTaintResult analysis, SinkArgument candidate, TaintValue taint) {
        SinkMatch sink = candidate.sink();
        int argumentIndex = candidate.argumentIndex();
        Expression argument = sink.call().call().arguments().get(argumentIndex);
        TaintTrace trace = analysis.traceToSinkArgument(sink, argumentIndex);

        List<TaintSeed> origins = taint.origins().stream()
                .sorted(Comparator.comparing(TaintSeed::id))
                .toList();
        List<FindingSource> sources = new ArrayList<>();
        List<FindingFlow> flows = new ArrayList<>();
        for (TaintSeed origin : origins) {
            SourceMatch match = analysis.sourceMatch(origin).orElseThrow(() ->
                    new IllegalStateException("Taint origin has no SourceMatch: " + origin.id()));
            FindingSource source = toSource(match, origin);
            sources.add(source);
            flows.add(new FindingFlow(source, toFlowSteps(trace, origin, source, sink, argumentIndex)));
        }

        FindingSink findingSink = new FindingSink(
                sink.ruleId(),
                sink.category(),
                sink.call().call().methodName(),
                argumentIndex,
                sink.location());
        String evidence = "Tainted external input reaches SQL text argument " + argumentIndex
                + " of sink rule " + sink.ruleId() + " (" + sink.call().call().methodName()
                + ") without a modeled safe SQL-text construction.";
        return new Finding(
                RULE_ID,
                VULNERABILITY_TYPE,
                CWE,
                SEVERITY,
                argument.location(),
                sources,
                findingSink,
                flows,
                evidence);
    }

    private FindingSource toSource(SourceMatch match, TaintSeed seed) {
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

    private List<FindingFlowStep> toFlowSteps(
            TaintTrace trace,
            TaintSeed origin,
            FindingSource source,
            SinkMatch sink,
            int argumentIndex) {
        TaintTraceStep sourceStep = trace.steps().stream()
                .filter(step -> step.seed().filter(origin::equals).isPresent())
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "Provenance trace does not contain source " + origin.id()));
        List<TaintTraceStep> path = shortestPath(trace, sourceStep);
        List<FindingFlowStep> steps = new ArrayList<>();
        for (TaintTraceStep step : path) {
            steps.add(toFlowStep(step, source));
        }
        Expression argument = sink.call().call().arguments().get(argumentIndex);
        steps.add(new FindingFlowStep(
                FindingFlowStepKind.SINK,
                argument.location(),
                "SQL text argument " + argumentIndex + " of " + sink.call().call().methodName()));
        return List.copyOf(steps);
    }

    private List<TaintTraceStep> shortestPath(TaintTrace trace, TaintTraceStep source) {
        Map<TaintTraceStep, List<TaintTraceStep>> outgoing = new HashMap<>();
        for (TaintTraceEdge edge : trace.edges()) {
            outgoing.computeIfAbsent(edge.source(), ignored -> new ArrayList<>()).add(edge.target());
        }
        outgoing.values().forEach(targets -> targets.sort(Comparator.comparingInt(TaintTraceStep::id)));

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
        throw new IllegalStateException("No provenance path from source to sink argument");
    }

    private List<TaintTraceStep> rebuildPath(
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

    private FindingFlowStep toFlowStep(TaintTraceStep step, FindingSource source) {
        return switch (step.kind()) {
            case SEED -> new FindingFlowStep(
                    FindingFlowStepKind.SOURCE, source.location(), source.summary());
            case DEFINITION -> definitionStep(step.definition().orElseThrow());
            case USE -> useStep(step.useSite().orElseThrow());
            case EXPRESSION -> expressionStep(step.expression().orElseThrow());
        };
    }

    private FindingFlowStep definitionStep(Definition definition) {
        return new FindingFlowStep(
                FindingFlowStepKind.DEFINITION,
                definition.location(),
                "Definition of " + definition.variable().name() + " (" + definition.kind() + ")");
    }

    private FindingFlowStep useStep(UseSite use) {
        return new FindingFlowStep(
                FindingFlowStepKind.USE,
                use.reference().location(),
                "Use of " + use.variable().name());
    }

    private FindingFlowStep expressionStep(Expression expression) {
        return new FindingFlowStep(
                FindingFlowStepKind.EXPRESSION, expression.location(), expressionSummary(expression));
    }

    private String expressionSummary(Expression expression) {
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

    private record PhysicalSinkKey(SourceLocation callLocation, int argumentIndex) {}

    private record SinkArgument(SinkMatch sink, int argumentIndex) {}
}
