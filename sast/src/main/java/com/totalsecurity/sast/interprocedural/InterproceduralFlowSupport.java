package com.totalsecurity.sast.interprocedural;

import com.totalsecurity.sast.dataflow.Definition;
import com.totalsecurity.sast.dataflow.UseSite;
import com.totalsecurity.sast.finding.FindingFlowStep;
import com.totalsecurity.sast.finding.FindingFlowStepKind;
import com.totalsecurity.sast.finding.FindingSource;
import com.totalsecurity.sast.finding.FindingSourceKind;
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
import com.totalsecurity.sast.rule.source.ExpressionSourceMatch;
import com.totalsecurity.sast.rule.source.ParameterSourceMatch;
import com.totalsecurity.sast.rule.source.SourceMatch;
import com.totalsecurity.sast.taint.TaintAnalysisResult;
import com.totalsecurity.sast.taint.TaintSeed;
import com.totalsecurity.sast.taint.TaintTrace;
import com.totalsecurity.sast.taint.TaintTraceEdge;
import com.totalsecurity.sast.taint.TaintTraceStep;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

final class InterproceduralFlowSupport {
    private InterproceduralFlowSupport() {}

    static FindingSource source(SourceMatch match, TaintSeed seed) {
        return switch (match) {
            case ParameterSourceMatch parameter -> new FindingSource(
                    parameter.ruleId(), seed.id(), FindingSourceKind.PARAMETER,
                    parameter.location(), "External parameter " + parameter.parameter().name(),
                    parameter.evidence());
            case ExpressionSourceMatch expression -> new FindingSource(
                    expression.ruleId(), seed.id(), FindingSourceKind.EXPRESSION,
                    expression.location(),
                    "External return value of " + expression.expression().call().methodName(),
                    expression.evidence());
        };
    }

    static List<FindingFlowStep> flowTo(
            TaintAnalysisResult taint, Expression endpoint, TaintSeed seed, FindingSource source) {
        TaintTrace trace = taint.traceTo(endpoint);
        TaintTraceStep sourceStep = trace.steps().stream()
                .filter(step -> step.seed().filter(seed::equals).isPresent())
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Trace lacks origin " + seed.id()));
        List<FindingFlowStep> result = new ArrayList<>();
        for (TaintTraceStep step : shortestPath(trace, sourceStep)) {
            result.add(toStep(step, source));
        }
        return List.copyOf(result);
    }

    static List<FindingFlowStep> syntheticFlowTo(
            TaintAnalysisResult taint, Expression endpoint, TaintSeed seed) {
        TaintTrace trace = taint.traceTo(endpoint);
        TaintTraceStep sourceStep = trace.steps().stream()
                .filter(step -> step.seed().filter(seed::equals).isPresent())
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Synthetic trace lacks origin " + seed.id()));
        List<FindingFlowStep> result = new ArrayList<>();
        for (TaintTraceStep step : shortestPath(trace, sourceStep)) {
            if (step.kind() != com.totalsecurity.sast.taint.TaintTraceStepKind.SEED) {
                result.add(toStep(step, null));
            }
        }
        return List.copyOf(result);
    }

    private static List<TaintTraceStep> shortestPath(TaintTrace trace, TaintTraceStep source) {
        Map<TaintTraceStep, List<TaintTraceStep>> outgoing = new HashMap<>();
        for (TaintTraceEdge edge : trace.edges()) {
            outgoing.computeIfAbsent(edge.source(), ignored -> new ArrayList<>()).add(edge.target());
        }
        outgoing.values().forEach(values -> values.sort(Comparator.comparingInt(TaintTraceStep::id)));
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
        throw new IllegalStateException("No provenance path to interprocedural endpoint");
    }

    private static FindingFlowStep toStep(TaintTraceStep step, FindingSource source) {
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
                FindingFlowStepKind.DEFINITION, definition.location(),
                "Definition of " + definition.variable().name() + " (" + definition.kind() + ")");
    }

    private static FindingFlowStep useStep(UseSite use) {
        return new FindingFlowStep(
                FindingFlowStepKind.USE, use.reference().location(),
                "Use of " + use.variable().name());
    }

    private static FindingFlowStep expressionStep(Expression expression) {
        String summary = switch (expression) {
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
        return new FindingFlowStep(FindingFlowStepKind.EXPRESSION, expression.location(), summary);
    }
}
