package com.totalsecurity.sast.detector.xss;

import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.Definition;
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
import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.rule.context.CallSiteContextResolver;
import com.totalsecurity.sast.taint.DefinitionTaintSeed;
import com.totalsecurity.sast.taint.ExpressionTaintSeed;
import com.totalsecurity.sast.taint.TaintAnalysisResult;
import com.totalsecurity.sast.taint.TaintSeed;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Raw/escaped HTML-output classification without registering a universal taint sanitizer. */
public final class HtmlOutputSafetyAnalysis {
    private static final String HTML_UTILS = "org.springframework.web.util.HtmlUtils";

    private final TaintAnalysisResult taint;
    private final DataFlowResult dataFlow;
    private final CallSiteContextResolver calls;
    private final Set<Definition> definitionSeeds = new LinkedHashSet<>();
    private final Set<Expression> expressionSeeds =
            Collections.newSetFromMap(new IdentityHashMap<>());
    private final Map<Definition, HtmlOutputSafety> definitions = new IdentityHashMap<>();
    private final Map<Expression, HtmlOutputSafety> expressions = new IdentityHashMap<>();
    private final Set<Definition> visitingDefinitions =
            Collections.newSetFromMap(new IdentityHashMap<>());
    private final Set<Expression> visitingExpressions =
            Collections.newSetFromMap(new IdentityHashMap<>());

    public HtmlOutputSafetyAnalysis(
            JavaFileInfo file,
            ClassInfo enclosingClass,
            MethodInfo method,
            RuleAwareTaintResult analysis) {
        Objects.requireNonNull(analysis, "analysis");
        this.taint = analysis.taintResult();
        this.dataFlow = taint.dataFlow();
        this.calls = new CallSiteContextResolver(file, enclosingClass, method, dataFlow);
        for (TaintSeed seed : analysis.taintSeeds()) {
            if (seed instanceof DefinitionTaintSeed definitionSeed) {
                definitionSeeds.add(definitionSeed.definition());
            } else if (seed instanceof ExpressionTaintSeed expressionSeed) {
                expressionSeeds.add(expressionSeed.expression());
            }
        }
    }

    public HtmlOutputSafety classify(Expression expression) {
        Objects.requireNonNull(expression, "expression");
        return evaluate(expression);
    }

    private HtmlOutputSafety evaluate(Expression expression) {
        HtmlOutputSafety cached = expressions.get(expression);
        if (cached != null) {
            return cached;
        }
        if (!visitingExpressions.add(expression)) {
            return HtmlOutputSafety.UNKNOWN;
        }
        HtmlOutputSafety result;
        if (expressionSeeds.contains(expression)) {
            result = HtmlOutputSafety.RAW_TAINTED;
        } else {
            result = switch (expression) {
                case VariableReference reference -> evaluateReference(reference);
                case Literal ignored -> HtmlOutputSafety.CLEAN;
                case BinaryExpression binary ->
                        evaluate(binary.left()).join(evaluate(binary.right()));
                case AssignmentExpression assignment ->
                        evaluate(assignment.assignment().right());
                case MethodCallExpression call -> evaluateMethodCall(call);
                case ParenthesizedExpression parenthesized ->
                        evaluate(parenthesized.expression());
                case ObjectCreationExpression ignored -> fromTaint(expression);
                case FieldAccessExpression ignored -> fromTaint(expression);
                case UnknownExpression ignored -> HtmlOutputSafety.UNKNOWN;
            };
        }
        visitingExpressions.remove(expression);
        expressions.put(expression, result);
        return result;
    }

    private HtmlOutputSafety evaluateReference(VariableReference reference) {
        Set<Definition> reaching = dataFlow.reachingDefinitions(reference);
        if (reaching.isEmpty()) {
            return fromTaint(reference);
        }
        HtmlOutputSafety merged = null;
        for (Definition definition : reaching) {
            HtmlOutputSafety value = evaluateDefinition(definition);
            merged = merged == null ? value : merged.join(value);
        }
        return merged == null ? HtmlOutputSafety.UNKNOWN : merged;
    }

    private HtmlOutputSafety evaluateDefinition(Definition definition) {
        HtmlOutputSafety cached = definitions.get(definition);
        if (cached != null) {
            return cached;
        }
        if (definitionSeeds.contains(definition)) {
            return HtmlOutputSafety.RAW_TAINTED;
        }
        if (!visitingDefinitions.add(definition)) {
            return HtmlOutputSafety.UNKNOWN;
        }
        HtmlOutputSafety result = definition.assignedExpression()
                .map(this::evaluate)
                .orElseGet(() -> fromTaint(definition));
        visitingDefinitions.remove(definition);
        definitions.put(definition, result);
        return result;
    }

    private HtmlOutputSafety evaluateMethodCall(MethodCallExpression call) {
        CallSiteContext context = calls.resolve(call);
        if (context.receiverQualifiedType().filter(HTML_UTILS::equals).isPresent()
                && context.methodName().equals("htmlEscape")
                && context.argumentCount() == 1
                && context.argumentHasType(0, "java.lang.String")) {
            return switch (evaluate(context.arguments().getFirst())) {
                case CLEAN -> HtmlOutputSafety.CLEAN;
                case RAW_TAINTED, HTML_ESCAPED -> HtmlOutputSafety.HTML_ESCAPED;
                case UNKNOWN -> HtmlOutputSafety.UNKNOWN;
            };
        }
        return fromTaint(call);
    }

    private HtmlOutputSafety fromTaint(Expression expression) {
        try {
            return switch (taint.taintOf(expression).state()) {
                case CLEAN -> HtmlOutputSafety.CLEAN;
                case TAINTED -> HtmlOutputSafety.RAW_TAINTED;
                case UNKNOWN -> HtmlOutputSafety.UNKNOWN;
            };
        } catch (IllegalArgumentException ignored) {
            return HtmlOutputSafety.UNKNOWN;
        }
    }

    private HtmlOutputSafety fromTaint(Definition definition) {
        try {
            return switch (taint.taintOf(definition).state()) {
                case CLEAN -> HtmlOutputSafety.CLEAN;
                case TAINTED -> HtmlOutputSafety.RAW_TAINTED;
                case UNKNOWN -> HtmlOutputSafety.UNKNOWN;
            };
        } catch (IllegalArgumentException ignored) {
            return HtmlOutputSafety.UNKNOWN;
        }
    }
}
