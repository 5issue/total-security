package com.totalsecurity.sast.detector.redirect;

import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.Definition;
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
import com.totalsecurity.sast.taint.DefinitionTaintSeed;
import com.totalsecurity.sast.taint.ExpressionTaintSeed;
import com.totalsecurity.sast.taint.TaintAnalysisResult;
import com.totalsecurity.sast.taint.TaintSeed;
import com.totalsecurity.sast.taint.TaintState;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Intraprocedural shape analysis for redirect targets. It reuses stable reaching definitions and
 * expression taint; it does not inspect source text as a substitute for semantic IR.
 */
public final class RedirectTargetControlAnalysis {
    private static final Set<String> RECEIVER_PRESERVING_STRING_METHODS =
            Set.of("trim", "strip", "substring", "toLowerCase", "toUpperCase");

    private final TaintAnalysisResult taint;
    private final DataFlowResult dataFlow;
    private final Set<Definition> definitionSeeds = new LinkedHashSet<>();
    private final Set<Expression> expressionSeeds =
            Collections.newSetFromMap(new IdentityHashMap<>());
    private final Map<Definition, ControlValue> definitions = new IdentityHashMap<>();
    private final Map<Expression, ControlValue> expressions = new IdentityHashMap<>();
    private final Set<Definition> visitingDefinitions =
            Collections.newSetFromMap(new IdentityHashMap<>());
    private final Set<Expression> visitingExpressions =
            Collections.newSetFromMap(new IdentityHashMap<>());

    public RedirectTargetControlAnalysis(RuleAwareTaintResult analysis) {
        Objects.requireNonNull(analysis, "analysis");
        this.taint = analysis.taintResult();
        this.dataFlow = taint.dataFlow();
        for (TaintSeed seed : analysis.taintSeeds()) {
            if (seed instanceof DefinitionTaintSeed definitionSeed) {
                definitionSeeds.add(definitionSeed.definition());
            } else if (seed instanceof ExpressionTaintSeed expressionSeed) {
                expressionSeeds.add(expressionSeed.expression());
            }
        }
    }

    public RedirectTargetControl classify(Expression expression) {
        Objects.requireNonNull(expression, "expression");
        return evaluate(expression).control();
    }

    private ControlValue evaluate(Expression expression) {
        ControlValue cached = expressions.get(expression);
        if (cached != null) {
            return cached;
        }
        if (!visitingExpressions.add(expression)) {
            return ControlValue.unknown();
        }
        ControlValue value;
        if (expressionSeeds.contains(expression)) {
            value = ControlValue.fullyControlled();
        } else {
            value = switch (expression) {
                case VariableReference reference -> evaluateReference(reference);
                case Literal literal -> evaluateLiteral(literal);
                case BinaryExpression binary -> evaluateBinary(binary);
                case AssignmentExpression assignment -> evaluate(assignment.assignment().right());
                case MethodCallExpression call -> evaluateMethodCall(call);
                case ParenthesizedExpression parenthesized -> evaluate(parenthesized.expression());
                case ObjectCreationExpression ignored -> fromTaint(expression);
                case FieldAccessExpression ignored -> fromTaint(expression);
                case UnknownExpression ignored -> ControlValue.unknown();
            };
        }
        visitingExpressions.remove(expression);
        expressions.put(expression, value);
        return value;
    }

    private ControlValue evaluateReference(VariableReference reference) {
        Set<Definition> reaching = dataFlow.reachingDefinitions(reference);
        if (reaching.isEmpty()) {
            return fromTaint(reference);
        }
        ControlValue merged = null;
        for (Definition definition : reaching) {
            ControlValue value = evaluateDefinition(definition);
            merged = merged == null ? value : merged.join(value);
        }
        return merged == null ? ControlValue.unknown() : merged;
    }

    private ControlValue evaluateDefinition(Definition definition) {
        ControlValue cached = definitions.get(definition);
        if (cached != null) {
            return cached;
        }
        if (definitionSeeds.contains(definition)) {
            return ControlValue.fullyControlled();
        }
        if (!visitingDefinitions.add(definition)) {
            return ControlValue.unknown();
        }
        ControlValue value = definition.assignedExpression()
                .map(this::evaluate)
                .orElseGet(() -> fromTaint(definition));
        visitingDefinitions.remove(definition);
        definitions.put(definition, value);
        return value;
    }

    private ControlValue evaluateLiteral(Literal literal) {
        if (!literal.kind().equals("string_literal")) {
            return ControlValue.clean();
        }
        return literal.source().equals("\"\"")
                ? ControlValue.emptyClean()
                : ControlValue.nonEmptyClean();
    }

    private ControlValue evaluateBinary(BinaryExpression binary) {
        if (!binary.operator().equals("+")) {
            return fromTaint(binary);
        }
        return concatenate(evaluate(binary.left()), evaluate(binary.right()));
    }

    private ControlValue evaluateMethodCall(MethodCallExpression call) {
        ControlValue fallback = fromTaint(call);
        if (fallback.control() != RedirectTargetControl.FULLY_CONTROLLED) {
            return fallback;
        }
        if (call.call().methodName().equals("concat")
                && call.call().receiver().isPresent()
                && call.call().arguments().size() == 1) {
            return concatenate(
                    evaluate(call.call().receiver().orElseThrow()),
                    evaluate(call.call().arguments().getFirst()));
        }
        if (RECEIVER_PRESERVING_STRING_METHODS.contains(call.call().methodName())
                && call.call().receiver().isPresent()) {
            ControlValue receiver = evaluate(call.call().receiver().orElseThrow());
            return receiver.control() == RedirectTargetControl.FULLY_CONTROLLED
                    ? ControlValue.fullyControlled()
                    : ControlValue.unknown();
        }
        return ControlValue.unknown();
    }

    private ControlValue concatenate(ControlValue left, ControlValue right) {
        return switch (left.control()) {
            case FULLY_CONTROLLED -> ControlValue.fullyControlled();
            case FIXED_PREFIX -> ControlValue.fixedPrefix();
            case UNKNOWN -> ControlValue.unknown();
            case CLEAN -> {
                if (right.control() == RedirectTargetControl.CLEAN) {
                    yield new ControlValue(
                            RedirectTargetControl.CLEAN,
                            left.definitelyEmpty() && right.definitelyEmpty(),
                            left.definitelyNonEmpty() || right.definitelyNonEmpty());
                }
                if (left.definitelyNonEmpty()) {
                    yield ControlValue.fixedPrefix();
                }
                if (left.definitelyEmpty()) {
                    yield right;
                }
                yield ControlValue.unknown();
            }
        };
    }

    private ControlValue fromTaint(Expression expression) {
        try {
            return switch (taint.taintOf(expression).state()) {
                case CLEAN -> ControlValue.clean();
                case TAINTED -> ControlValue.fullyControlled();
                case UNKNOWN -> ControlValue.unknown();
            };
        } catch (IllegalArgumentException ignored) {
            return ControlValue.unknown();
        }
    }

    private ControlValue fromTaint(Definition definition) {
        try {
            return switch (taint.taintOf(definition).state()) {
                case CLEAN -> ControlValue.clean();
                case TAINTED -> ControlValue.fullyControlled();
                case UNKNOWN -> ControlValue.unknown();
            };
        } catch (IllegalArgumentException ignored) {
            return ControlValue.unknown();
        }
    }

    private record ControlValue(
            RedirectTargetControl control,
            boolean definitelyEmpty,
            boolean definitelyNonEmpty) {
        private ControlValue {
            Objects.requireNonNull(control, "control");
            if (definitelyEmpty && definitelyNonEmpty) {
                throw new IllegalArgumentException("A clean value cannot be both empty and non-empty");
            }
            if (control != RedirectTargetControl.CLEAN
                    && (definitelyEmpty || definitelyNonEmpty)) {
                throw new IllegalArgumentException("Only clean values carry literal certainty");
            }
        }

        private static ControlValue clean() {
            return new ControlValue(RedirectTargetControl.CLEAN, false, false);
        }

        private static ControlValue emptyClean() {
            return new ControlValue(RedirectTargetControl.CLEAN, true, false);
        }

        private static ControlValue nonEmptyClean() {
            return new ControlValue(RedirectTargetControl.CLEAN, false, true);
        }

        private static ControlValue fullyControlled() {
            return new ControlValue(RedirectTargetControl.FULLY_CONTROLLED, false, false);
        }

        private static ControlValue fixedPrefix() {
            return new ControlValue(RedirectTargetControl.FIXED_PREFIX, false, false);
        }

        private static ControlValue unknown() {
            return new ControlValue(RedirectTargetControl.UNKNOWN, false, false);
        }

        private ControlValue join(ControlValue other) {
            RedirectTargetControl merged = control.join(other.control);
            if (merged != RedirectTargetControl.CLEAN) {
                return switch (merged) {
                    case FULLY_CONTROLLED -> fullyControlled();
                    case FIXED_PREFIX -> fixedPrefix();
                    case UNKNOWN -> unknown();
                    case CLEAN -> throw new IllegalStateException("Unexpected clean merge");
                };
            }
            return new ControlValue(
                    RedirectTargetControl.CLEAN,
                    definitelyEmpty && other.definitelyEmpty,
                    definitelyNonEmpty && other.definitelyNonEmpty);
        }
    }
}
