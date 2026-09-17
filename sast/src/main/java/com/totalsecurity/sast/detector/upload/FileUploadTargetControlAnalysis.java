package com.totalsecurity.sast.detector.upload;

import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.Definition;
import com.totalsecurity.sast.finding.FileUploadEvidence;
import com.totalsecurity.sast.finding.FileUploadEvidenceKind;
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
import com.totalsecurity.sast.taint.TaintSeed;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Intraprocedural analysis of the final filename component used by an upload target. It follows
 * ordered binary concatenation and stable reaching definitions; arbitrary taint is not treated as
 * proof that the extension remains attacker-controlled.
 */
public final class FileUploadTargetControlAnalysis {
    private static final String STRING = "java.lang.String";
    private static final String PATH = "java.nio.file.Path";
    private static final String PATHS = "java.nio.file.Paths";
    private static final String FILE = "java.io.File";

    private final DataFlowResult dataFlow;
    private final CallSiteContextResolver calls;
    private final Map<Definition, TaintSeed> definitionSeeds = new IdentityHashMap<>();
    private final Map<Expression, TaintSeed> expressionSeeds = new IdentityHashMap<>();
    private final Map<Definition, ControlValue> definitions = new IdentityHashMap<>();
    private final Map<Expression, ControlValue> expressions = new IdentityHashMap<>();
    private final Set<Definition> visitingDefinitions =
            Collections.newSetFromMap(new IdentityHashMap<>());
    private final Set<Expression> visitingExpressions =
            Collections.newSetFromMap(new IdentityHashMap<>());

    public FileUploadTargetControlAnalysis(
            RuleAwareTaintResult analysis, CallSiteContextResolver calls) {
        Objects.requireNonNull(analysis, "analysis");
        this.dataFlow = analysis.taintResult().dataFlow();
        this.calls = Objects.requireNonNull(calls, "calls");
        for (TaintSeed seed : analysis.taintSeeds()) {
            if (seed instanceof DefinitionTaintSeed definitionSeed) {
                definitionSeeds.put(definitionSeed.definition(), seed);
            } else if (seed instanceof ExpressionTaintSeed expressionSeed) {
                expressionSeeds.put(expressionSeed.expression(), seed);
            }
        }
    }

    public FileUploadTargetAssessment classify(Expression expression) {
        Objects.requireNonNull(expression, "expression");
        ControlValue value = evaluate(expression);
        return new FileUploadTargetAssessment(
                value.control(), value.origins(), value.evidence().stream().toList());
    }

    private ControlValue evaluate(Expression expression) {
        ControlValue cached = expressions.get(expression);
        if (cached != null) {
            return cached;
        }
        if (!visitingExpressions.add(expression)) {
            return ControlValue.unknown();
        }
        TaintSeed expressionSeed = expressionSeeds.get(expression);
        ControlValue value;
        if (expressionSeed != null && calls.qualifiedTypeOf(expression).filter(STRING::equals).isPresent()) {
            value = ControlValue.attacker(expressionSeed);
        } else {
            value = switch (expression) {
                case VariableReference reference -> evaluateReference(reference);
                case Literal literal -> evaluateLiteral(literal);
                case BinaryExpression binary -> evaluateBinary(binary);
                case AssignmentExpression assignment -> evaluate(assignment.assignment().right());
                case MethodCallExpression call -> evaluateMethodCall(call);
                case ObjectCreationExpression creation -> evaluateObjectCreation(creation);
                case ParenthesizedExpression parenthesized -> evaluate(parenthesized.expression());
                case FieldAccessExpression ignored -> ControlValue.unknown();
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
            return ControlValue.unknown();
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
        TaintSeed seed = definitionSeeds.get(definition);
        if (seed != null
                && calls.types().qualifyType(definition.variable().declaredType())
                        .filter(STRING::equals)
                        .isPresent()) {
            ControlValue value = ControlValue.attacker(seed);
            definitions.put(definition, value);
            return value;
        }
        if (!visitingDefinitions.add(definition)) {
            return ControlValue.unknown();
        }
        ControlValue value = definition.assignedExpression()
                .map(this::evaluate)
                .orElseGet(ControlValue::unknown);
        visitingDefinitions.remove(definition);
        definitions.put(definition, value);
        return value;
    }

    private static ControlValue evaluateLiteral(Literal literal) {
        if (!literal.kind().equals("string_literal")) {
            return ControlValue.cleanUnknown();
        }
        return decodeStringLiteral(literal.source())
                .map(ControlValue::cleanLiteral)
                .orElseGet(ControlValue::cleanUnknown);
    }

    private ControlValue evaluateBinary(BinaryExpression binary) {
        if (!binary.operator().equals("+")) {
            return ControlValue.unknown();
        }
        return concatenate(evaluate(binary.left()), evaluate(binary.right()));
    }

    private ControlValue evaluateMethodCall(MethodCallExpression call) {
        CallSiteContext context = calls.resolve(call);
        if (isPathFactory(context)) {
            ControlValue filename = evaluate(context.arguments().getLast());
            return filename.withEvidence(new FileUploadEvidence(
                    FileUploadEvidenceKind.TARGET_CONSTRUCTION,
                    context.receiverQualifiedType().orElseThrow() + "." + context.methodName()
                            + " target construction",
                    call.location()));
        }
        if (context.receiverQualifiedType().filter(PATH::equals).isPresent()
                && context.methodName().equals("resolve")
                && context.argumentCount() == 1
                && (context.argumentHasType(0, STRING) || context.argumentHasType(0, PATH))) {
            return evaluate(context.arguments().getFirst()).withEvidence(new FileUploadEvidence(
                    FileUploadEvidenceKind.TARGET_CONSTRUCTION,
                    PATH + ".resolve target construction",
                    call.location()));
        }
        if (context.receiverQualifiedType().filter(STRING::equals).isPresent()
                && context.methodName().equals("concat")
                && context.argumentCount() == 1
                && context.receiver().isPresent()
                && context.argumentHasType(0, STRING)) {
            return concatenate(
                    evaluate(context.receiver().orElseThrow()),
                    evaluate(context.arguments().getFirst()));
        }
        return ControlValue.unknown();
    }

    private ControlValue evaluateObjectCreation(ObjectCreationExpression creation) {
        if (calls.types().qualifyType(creation.typeName()).filter(FILE::equals).isEmpty()) {
            return ControlValue.unknown();
        }
        ControlValue filename;
        if (creation.arguments().size() == 1
                && calls.qualifiedTypeShapeOf(creation.arguments().getFirst())
                        .filter(STRING::equals)
                        .isPresent()) {
            filename = evaluate(creation.arguments().getFirst());
        } else if (creation.arguments().size() == 2
                && calls.qualifiedTypeShapeOf(creation.arguments().get(1))
                        .filter(STRING::equals)
                        .isPresent()
                && calls.qualifiedTypeShapeOf(creation.arguments().getFirst())
                        .filter(type -> type.equals(STRING) || type.equals(FILE))
                        .isPresent()) {
            filename = evaluate(creation.arguments().get(1));
        } else {
            return ControlValue.unknown();
        }
        return filename.withEvidence(new FileUploadEvidence(
                FileUploadEvidenceKind.TARGET_CONSTRUCTION,
                FILE + " exact target construction",
                creation.location()));
    }

    private static boolean isPathFactory(CallSiteContext context) {
        if (context.argumentCount() < 1
                || context.argumentQualifiedTypes().stream()
                        .anyMatch(type -> type.filter(STRING::equals).isEmpty())) {
            return false;
        }
        return context.receiverQualifiedType().filter(PATH::equals).isPresent()
                        && context.methodName().equals("of")
                || context.receiverQualifiedType().filter(PATHS::equals).isPresent()
                        && context.methodName().equals("get");
    }

    private static ControlValue concatenate(ControlValue left, ControlValue right) {
        LinkedHashSet<TaintSeed> origins = union(left.origins(), right.origins());
        LinkedHashSet<FileUploadEvidence> evidence = union(left.evidence(), right.evidence());
        if (right.control() == FileUploadTargetControl.ATTACKER_TYPE_CONTROLLED) {
            return ControlValue.attacker(origins, evidence, right.fixedTail());
        }
        if (right.control() == FileUploadTargetControl.FIXED_EXTENSION) {
            return ControlValue.fixed(origins, evidence, right.fixedTail());
        }
        if (right.control() == FileUploadTargetControl.UNKNOWN) {
            return ControlValue.unknown(origins, evidence);
        }
        if (right.exactClean().isPresent()) {
            String suffix = right.exactClean().orElseThrow();
            if (left.control() == FileUploadTargetControl.CLEAN) {
                if (left.exactClean().isPresent()) {
                    return ControlValue.cleanLiteral(left.exactClean().orElseThrow() + suffix);
                }
                return ControlValue.cleanUnknown();
            }
            if (left.control() == FileUploadTargetControl.UNKNOWN) {
                return establishesFixedExtension(suffix)
                        ? ControlValue.fixed(origins, evidence, suffix)
                        : ControlValue.unknown(origins, evidence);
            }
            String trailing = left.fixedTail() + suffix;
            return establishesFixedExtension(trailing)
                    ? ControlValue.fixed(origins, evidence, trailing)
                    : ControlValue.attacker(origins, evidence, trailing);
        }
        if (left.control() == FileUploadTargetControl.CLEAN) {
            return ControlValue.cleanUnknown();
        }
        return ControlValue.unknown(origins, evidence);
    }

    private static boolean establishesFixedExtension(String suffix) {
        int dot = suffix.lastIndexOf('.');
        if (dot < 0 || dot == suffix.length() - 1) {
            return false;
        }
        for (int index = dot + 1; index < suffix.length(); index++) {
            char value = suffix.charAt(index);
            if (!Character.isLetterOrDigit(value)) {
                return false;
            }
        }
        return suffix.length() - dot - 1 <= 16;
    }

    private static Optional<String> decodeStringLiteral(String source) {
        if (source.length() < 2 || source.charAt(0) != '"'
                || source.charAt(source.length() - 1) != '"') {
            return Optional.empty();
        }
        String body = source.substring(1, source.length() - 1);
        StringBuilder decoded = new StringBuilder(body.length());
        boolean escaping = false;
        for (int index = 0; index < body.length(); index++) {
            char current = body.charAt(index);
            if (!escaping && current == '\\') {
                escaping = true;
            } else if (!escaping) {
                decoded.append(current);
            } else {
                decoded.append(switch (current) {
                    case 't' -> '\t';
                    case 'n' -> '\n';
                    case 'r' -> '\r';
                    case 'b' -> '\b';
                    case 'f' -> '\f';
                    case '"' -> '"';
                    case '\'' -> '\'';
                    case '\\' -> '\\';
                    default -> current;
                });
                escaping = false;
            }
        }
        return escaping ? Optional.empty() : Optional.of(decoded.toString());
    }

    private static <T> LinkedHashSet<T> union(Set<T> left, Set<T> right) {
        LinkedHashSet<T> merged = new LinkedHashSet<>(left);
        merged.addAll(right);
        return merged;
    }

    private record ControlValue(
            FileUploadTargetControl control,
            Set<TaintSeed> origins,
            Set<FileUploadEvidence> evidence,
            Optional<String> exactClean,
            String fixedTail) {
        private ControlValue {
            Objects.requireNonNull(control, "control");
            origins = Set.copyOf(origins);
            evidence = Set.copyOf(evidence);
            exactClean = Objects.requireNonNull(exactClean, "exactClean");
            Objects.requireNonNull(fixedTail, "fixedTail");
        }

        private static ControlValue attacker(TaintSeed seed) {
            return attacker(Set.of(seed), Set.of(), "");
        }

        private static ControlValue attacker(
                Set<TaintSeed> origins, Set<FileUploadEvidence> evidence, String fixedTail) {
            return new ControlValue(
                    FileUploadTargetControl.ATTACKER_TYPE_CONTROLLED,
                    origins, evidence, Optional.empty(), fixedTail);
        }

        private static ControlValue fixed(
                Set<TaintSeed> origins, Set<FileUploadEvidence> evidence, String fixedTail) {
            return new ControlValue(
                    FileUploadTargetControl.FIXED_EXTENSION,
                    origins, evidence, Optional.empty(), fixedTail);
        }

        private static ControlValue cleanLiteral(String value) {
            return new ControlValue(
                    FileUploadTargetControl.CLEAN,
                    Set.of(), Set.of(), Optional.of(value), "");
        }

        private static ControlValue cleanUnknown() {
            return new ControlValue(
                    FileUploadTargetControl.CLEAN,
                    Set.of(), Set.of(), Optional.empty(), "");
        }

        private static ControlValue unknown() {
            return unknown(Set.of(), Set.of());
        }

        private static ControlValue unknown(
                Set<TaintSeed> origins, Set<FileUploadEvidence> evidence) {
            return new ControlValue(
                    FileUploadTargetControl.UNKNOWN,
                    origins, evidence, Optional.empty(), "");
        }

        private ControlValue withEvidence(FileUploadEvidence item) {
            LinkedHashSet<FileUploadEvidence> merged = new LinkedHashSet<>(evidence);
            merged.add(item);
            return new ControlValue(control, origins, merged, exactClean, fixedTail);
        }

        private ControlValue join(ControlValue other) {
            FileUploadTargetControl joined = control.join(other.control);
            LinkedHashSet<TaintSeed> mergedOrigins = union(origins, other.origins);
            LinkedHashSet<FileUploadEvidence> mergedEvidence = union(evidence, other.evidence);
            if (joined == FileUploadTargetControl.CLEAN) {
                Optional<String> sameLiteral = exactClean.isPresent()
                                && exactClean.equals(other.exactClean)
                        ? exactClean
                        : Optional.empty();
                return new ControlValue(joined, mergedOrigins, mergedEvidence, sameLiteral, "");
            }
            if (joined == FileUploadTargetControl.ATTACKER_TYPE_CONTROLLED) {
                return attacker(mergedOrigins, mergedEvidence, "");
            }
            if (joined == FileUploadTargetControl.FIXED_EXTENSION) {
                return fixed(mergedOrigins, mergedEvidence, "");
            }
            return unknown(mergedOrigins, mergedEvidence);
        }
    }
}
