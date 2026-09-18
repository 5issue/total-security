package com.totalsecurity.sast.rule.context;

import com.totalsecurity.sast.cfg.BasicBlock;
import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.ir.AssignmentInfo;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.MethodKind;
import com.totalsecurity.sast.ir.TypeKind;
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
    private final ProjectTypeLookup projectTypes;

    public CallSiteContextResolver(
            JavaFileInfo file,
            ClassInfo enclosingClass,
            MethodInfo enclosingMethod,
            DataFlowResult dataFlow) {
        this(file, enclosingClass, enclosingMethod, dataFlow, ProjectTypeLookup.none());
    }

    public CallSiteContextResolver(
            JavaFileInfo file,
            ClassInfo enclosingClass,
            MethodInfo enclosingMethod,
            DataFlowResult dataFlow,
            Predicate<String> projectTypeExists) {
        this(file, enclosingClass, enclosingMethod, dataFlow,
                ProjectTypeLookup.existenceOnly(projectTypeExists));
    }

    public CallSiteContextResolver(
            JavaFileInfo file,
            ClassInfo enclosingClass,
            MethodInfo enclosingMethod,
            DataFlowResult dataFlow,
            ProjectTypeLookup projectTypes) {
        this.file = Objects.requireNonNull(file, "file");
        this.enclosingClass = Objects.requireNonNull(enclosingClass, "enclosingClass");
        this.enclosingMethod = Objects.requireNonNull(enclosingMethod, "enclosingMethod");
        this.dataFlow = Objects.requireNonNull(dataFlow, "dataFlow");
        if (!dataFlow.graph().method().equals(enclosingMethod)) {
            throw new IllegalArgumentException("DataFlowResult belongs to a different method");
        }
        this.projectTypes = Objects.requireNonNull(projectTypes, "projectTypes");
        this.types = new LightweightTypeContext(file, projectTypes::contains);
    }

    public LightweightTypeContext types() {
        return types;
    }

    public CallSiteContext resolve(MethodCallExpression call) {
        Objects.requireNonNull(call, "call");
        Optional<String> declaredType = call.call().receiver().flatMap(this::declaredReceiverTypeOf);
        Optional<String> qualifiedType = declaredType.flatMap(types::qualifyType);
        Optional<RecordAccessorInfo> recordAccessor = exactRecordAccessor(call);
        Optional<EnumConstantReferenceInfo> enumConstantReceiver =
                call.call().receiver().flatMap(this::exactEnumConstant);
        return new CallSiteContext(
                file,
                enclosingClass,
                enclosingMethod,
                call,
                call.call().receiver(),
                declaredType,
                qualifiedType,
                recordAccessor,
                enumConstantReceiver,
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
        return exactEnumConstant(field).map(EnumConstantReferenceInfo::ownerQualifiedName);
    }

    private Optional<String> knownMethodReturnType(MethodCallExpression call) {
        Optional<String> receiverType = call.call().receiver().flatMap(this::qualifiedReceiverTypeOf);
        if (receiverType.isEmpty()) {
            return Optional.empty();
        }
        Optional<ProjectTypeDeclaration> owner = uniqueType(receiverType.orElseThrow());
        if (owner.isPresent() && owner.orElseThrow().type().kind() == TypeKind.RECORD
                && call.call().arguments().isEmpty()) {
            ProjectTypeDeclaration record = owner.orElseThrow();
            List<MethodInfo> explicit = record.type().methods().stream()
                    .filter(method -> method.kind() == MethodKind.METHOD)
                    .filter(method -> method.name().equals(call.call().methodName()))
                    .filter(method -> method.parameters().isEmpty())
                    .toList();
            if (explicit.size() == 1) {
                return explicit.getFirst().returnType()
                        .flatMap(type -> ownerTypes(record).qualifyTypeShape(type));
            }
            if (!explicit.isEmpty()) {
                return Optional.empty();
            }
            Optional<RecordAccessorInfo> accessor = exactRecordAccessor(call);
            if (accessor.isPresent()) {
                return accessor.map(RecordAccessorInfo::qualifiedReturnType);
            }
        }
        List<Optional<String>> argumentTypes = call.call().arguments().stream()
                .map(this::qualifiedTypeShapeOf)
                .toList();
        return KnownMethodReturnTypes.match(
                        receiverType.orElseThrow(), call.call().methodName(), argumentTypes)
                .map(KnownMethodReturnTypes.KnownMethod::returnType);
    }

    private Optional<RecordAccessorInfo> exactRecordAccessor(MethodCallExpression call) {
        if (call.call().arguments().size() != 0
                || call.call().receiver().isEmpty()
                || call.call().receiver().filter(this::isValueReceiver).isEmpty()) {
            return Optional.empty();
        }
        Optional<String> receiverType = call.call().receiver().flatMap(this::qualifiedReceiverTypeOf);
        if (receiverType.isEmpty()) {
            return Optional.empty();
        }
        Optional<ProjectTypeDeclaration> owner = uniqueType(receiverType.orElseThrow());
        if (owner.isEmpty() || owner.orElseThrow().type().kind() != TypeKind.RECORD) {
            return Optional.empty();
        }
        ProjectTypeDeclaration record = owner.orElseThrow();
        boolean explicit = record.type().methods().stream()
                .filter(method -> method.kind() == MethodKind.METHOD)
                .anyMatch(method -> method.name().equals(call.call().methodName())
                        && method.parameters().isEmpty());
        if (explicit) {
            return Optional.empty();
        }
        return record.type().recordComponents().stream()
                .filter(component -> component.name().equals(call.call().methodName()))
                .findFirst()
                .flatMap(component -> ownerTypes(record)
                        .qualifyTypeShape(component.declaredType())
                        .map(returnType -> new RecordAccessorInfo(
                                record.qualifiedName(), returnType, component)));
    }

    private Optional<EnumConstantReferenceInfo> exactEnumConstant(Expression expression) {
        if (!(expression instanceof FieldAccessExpression field)
                || !(field.target() instanceof VariableReference ownerReference)
                || isValueReference(ownerReference)) {
            return Optional.empty();
        }
        Optional<String> ownerName = types.qualifyType(ownerReference.name());
        if (ownerName.isEmpty()) {
            return Optional.empty();
        }
        Optional<ProjectTypeDeclaration> owner = uniqueType(ownerName.orElseThrow());
        if (owner.isEmpty() || owner.orElseThrow().type().kind() != TypeKind.ENUM) {
            return Optional.empty();
        }
        ProjectTypeDeclaration enumType = owner.orElseThrow();
        return enumType.type().enumConstants().stream()
                .filter(constant -> constant.name().equals(field.fieldName()))
                .findFirst()
                .map(constant -> new EnumConstantReferenceInfo(
                        enumType.qualifiedName(), constant));
    }

    private Optional<ProjectTypeDeclaration> uniqueType(String qualifiedName) {
        List<ProjectTypeDeclaration> declarations = projectTypes.declarations(qualifiedName);
        if (declarations.size() == 1) {
            return Optional.of(declarations.getFirst());
        }
        if (declarations.size() > 1) {
            return Optional.empty();
        }
        List<ProjectTypeDeclaration> local = file.types().stream()
                .filter(type -> localQualifiedName(type).equals(qualifiedName))
                .map(type -> new ProjectTypeDeclaration(qualifiedName, file, type))
                .toList();
        return local.size() == 1 ? Optional.of(local.getFirst()) : Optional.empty();
    }

    private LightweightTypeContext ownerTypes(ProjectTypeDeclaration owner) {
        return new LightweightTypeContext(owner.file(), projectTypes::contains);
    }

    private String localQualifiedName(ClassInfo type) {
        return file.packageName().map(name -> name + "." + type.name()).orElse(type.name());
    }

    private boolean isValueReference(VariableReference reference) {
        if (dataFlow.resolvedSymbol(reference).isPresent()) {
            return true;
        }
        return enclosingClass.fields().stream()
                .anyMatch(field -> field.name().equals(reference.name()));
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
