package com.totalsecurity.sast.rule.context;

import com.totalsecurity.sast.cfg.BasicBlock;
import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.ir.AssignmentInfo;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.VariableInfo;
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
import com.totalsecurity.sast.ir.statement.DoWhileStatement;
import com.totalsecurity.sast.ir.statement.EnhancedForStatement;
import com.totalsecurity.sast.ir.statement.ExpressionStatement;
import com.totalsecurity.sast.ir.statement.ForStatement;
import com.totalsecurity.sast.ir.statement.IfStatement;
import com.totalsecurity.sast.ir.statement.ReturnStatement;
import com.totalsecurity.sast.ir.statement.Statement;
import com.totalsecurity.sast.ir.statement.SwitchStatement;
import com.totalsecurity.sast.ir.statement.ThrowStatement;
import com.totalsecurity.sast.ir.statement.VariableDeclarationStatement;
import com.totalsecurity.sast.ir.statement.WhileStatement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

/** Resolves only direct declarations and imports already represented in the Java IR. */
public final class CallSiteContextResolver {
    private final JavaFileInfo file;
    private final ClassInfo enclosingClass;
    private final MethodInfo enclosingMethod;
    private final DataFlowResult dataFlow;
    private final LightweightTypeContext types;

    public CallSiteContextResolver(
            JavaFileInfo file,
            ClassInfo enclosingClass,
            MethodInfo enclosingMethod,
            DataFlowResult dataFlow) {
        this(file, enclosingClass, enclosingMethod, dataFlow, ignored -> false);
    }

    public CallSiteContextResolver(
            JavaFileInfo file,
            ClassInfo enclosingClass,
            MethodInfo enclosingMethod,
            DataFlowResult dataFlow,
            Predicate<String> projectTypeExists) {
        this.file = Objects.requireNonNull(file, "file");
        this.enclosingClass = Objects.requireNonNull(enclosingClass, "enclosingClass");
        this.enclosingMethod = Objects.requireNonNull(enclosingMethod, "enclosingMethod");
        this.dataFlow = Objects.requireNonNull(dataFlow, "dataFlow");
        if (!dataFlow.graph().method().equals(enclosingMethod)) {
            throw new IllegalArgumentException("DataFlowResult belongs to a different method");
        }
        this.types = new LightweightTypeContext(file, projectTypeExists);
    }

    public LightweightTypeContext types() {
        return types;
    }

    public CallSiteContext resolve(MethodCallExpression call) {
        Objects.requireNonNull(call, "call");
        Optional<String> declaredType = call.call().receiver().flatMap(this::declaredReceiverTypeOf);
        Optional<String> qualifiedType = declaredType.flatMap(types::qualifyType);
        return new CallSiteContext(
                file,
                enclosingClass,
                enclosingMethod,
                call,
                call.call().receiver(),
                declaredType,
                qualifiedType,
                call.call().receiver().map(this::isValueReceiver).orElse(false),
                call.call().methodName(),
                call.call().arguments(),
                call.call().arguments().stream().map(this::qualifiedTypeShapeOf).toList(),
                call.location(),
                types);
    }

    public List<CallSiteContext> callSites() {
        Set<Expression> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        List<MethodCallExpression> calls = new ArrayList<>();
        for (BasicBlock block : dataFlow.graph().blocks()) {
            if (!dataFlow.graph().reachableBlocks().contains(block)) {
                continue;
            }
            block.controlStatement().ifPresent(statement -> collectControl(statement, visited, calls));
            block.statements().forEach(statement -> collectStatement(statement, visited, calls));
        }
        return calls.stream().map(this::resolve).toList();
    }

    public Optional<String> declaredTypeOf(Expression expression) {
        return switch (expression) {
            case VariableReference reference -> declaredTypeOf(reference);
            case Literal literal -> literalType(literal);
            case ObjectCreationExpression creation -> Optional.of(creation.typeName());
            case ParenthesizedExpression parenthesized -> declaredTypeOf(parenthesized.expression());
            case AssignmentExpression assignment -> declaredTypeOf(assignment.assignment().right());
            case BinaryExpression binary -> isStringLike(binary.left()) || isStringLike(binary.right())
                    ? Optional.of("String")
                    : Optional.empty();
            case FieldAccessExpression field -> declaredTypeOf(field);
            case MethodCallExpression call -> knownMethodReturnType(call);
            case UnknownExpression ignored -> Optional.empty();
        };
    }

    public Optional<String> qualifiedTypeOf(Expression expression) {
        return declaredTypeOf(expression).flatMap(types::qualifyType);
    }

    public Optional<String> qualifiedTypeShapeOf(Expression expression) {
        return declaredTypeOf(expression).flatMap(types::qualifyTypeShape);
    }

    public boolean isStringLike(Expression expression) {
        return qualifiedTypeOf(expression).filter("java.lang.String"::equals).isPresent();
    }

    private static Optional<String> literalType(Literal literal) {
        if (literal.kind().equals("string_literal")) {
            return Optional.of("String");
        }
        if (literal.kind().equals("true") || literal.kind().equals("false")) {
            return Optional.of("boolean");
        }
        if (literal.kind().endsWith("integer_literal")) {
            String source = literal.source();
            return Optional.of(source.endsWith("l") || source.endsWith("L") ? "long" : "int");
        }
        return Optional.empty();
    }

    private Optional<String> declaredTypeOf(VariableReference reference) {
        if (reference.name().equals("this")) {
            return Optional.of(file.packageName()
                    .map(packageName -> packageName + "." + enclosingClass.name())
                    .orElse(enclosingClass.name()));
        }
        Optional<String> local = dataFlow.resolvedSymbol(reference).map(symbol -> symbol.declaredType());
        if (local.isPresent()) {
            return local;
        }
        return enclosingClass.fields().stream()
                .filter(field -> field.name().equals(reference.name()))
                .map(VariableInfo::type)
                .findFirst();
    }

    private Optional<String> declaredTypeOf(FieldAccessExpression field) {
        if (field.target() instanceof VariableReference target && target.name().equals("this")) {
            return enclosingClass.fields().stream()
                    .filter(candidate -> candidate.name().equals(field.fieldName()))
                    .map(VariableInfo::type)
                    .findFirst();
        }
        return Optional.empty();
    }

    private Optional<String> knownMethodReturnType(MethodCallExpression call) {
        Optional<String> receiverType = call.call().receiver().flatMap(this::qualifiedReceiverTypeOf);
        if (receiverType.isEmpty()) {
            return Optional.empty();
        }
        List<Optional<String>> argumentTypes = call.call().arguments().stream()
                .map(this::qualifiedTypeShapeOf)
                .toList();
        return KnownMethodReturnTypes.match(
                        receiverType.orElseThrow(), call.call().methodName(), argumentTypes)
                .map(KnownMethodReturnTypes.KnownMethod::returnType);
    }

    private Optional<String> declaredReceiverTypeOf(Expression receiver) {
        Optional<String> declared = declaredTypeOf(receiver);
        if (declared.isPresent()) {
            return declared;
        }
        if (receiver instanceof VariableReference typeReference) {
            return types.qualifyType(typeReference.name());
        }
        return Optional.empty();
    }

    private Optional<String> qualifiedReceiverTypeOf(Expression receiver) {
        return declaredReceiverTypeOf(receiver).flatMap(types::qualifyType);
    }

    private boolean isValueReceiver(Expression receiver) {
        if (!(receiver instanceof VariableReference reference)) {
            return true;
        }
        if (reference.name().equals("this") || reference.name().equals("super")) {
            return true;
        }
        if (dataFlow.resolvedSymbol(reference).isPresent()) {
            return true;
        }
        return enclosingClass.fields().stream()
                .anyMatch(field -> field.name().equals(reference.name()));
    }

    private void collectControl(
            Statement statement, Set<Expression> visited, List<MethodCallExpression> calls) {
        switch (statement) {
            case IfStatement conditional -> collect(conditional.condition(), visited, calls);
            case WhileStatement loop -> collect(loop.condition(), visited, calls);
            case DoWhileStatement loop -> collect(loop.condition(), visited, calls);
            case ForStatement loop -> {
                loop.condition().ifPresent(expression -> collect(expression, visited, calls));
                loop.updates().forEach(expression -> collect(expression, visited, calls));
            }
            case EnhancedForStatement loop -> collect(loop.iterable(), visited, calls);
            case SwitchStatement selection -> collect(selection.selector(), visited, calls);
            default -> {
                // CFG exposes supported control expressions through the cases above.
            }
        }
    }

    private void collectStatement(
            Statement statement, Set<Expression> visited, List<MethodCallExpression> calls) {
        switch (statement) {
            case VariableDeclarationStatement declaration -> declaration.variables().forEach(
                    variable -> variable.initializer().ifPresent(expression -> collect(expression, visited, calls)));
            case ExpressionStatement expression -> collect(expression.expression(), visited, calls);
            case ReturnStatement returned ->
                    returned.expression().ifPresent(expression -> collect(expression, visited, calls));
            case ThrowStatement thrown -> collect(thrown.expression(), visited, calls);
            default -> {
                // Nested statements are represented by their own CFG blocks.
            }
        }
    }

    private void collect(
            Expression expression, Set<Expression> visited, List<MethodCallExpression> calls) {
        if (!visited.add(expression)) {
            return;
        }
        switch (expression) {
            case VariableReference ignored -> {
            }
            case Literal ignored -> {
            }
            case UnknownExpression ignored -> {
            }
            case BinaryExpression binary -> {
                collect(binary.left(), visited, calls);
                collect(binary.right(), visited, calls);
            }
            case AssignmentExpression assignment -> {
                AssignmentInfo info = assignment.assignment();
                collect(info.left(), visited, calls);
                collect(info.right(), visited, calls);
            }
            case MethodCallExpression call -> {
                calls.add(call);
                call.call().receiver().ifPresent(receiver -> collect(receiver, visited, calls));
                call.call().arguments().forEach(argument -> collect(argument, visited, calls));
            }
            case ObjectCreationExpression creation ->
                    creation.arguments().forEach(argument -> collect(argument, visited, calls));
            case FieldAccessExpression field -> collect(field.target(), visited, calls);
            case ParenthesizedExpression parenthesized -> collect(parenthesized.expression(), visited, calls);
        }
    }
}
