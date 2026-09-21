package com.totalsecurity.sast.detector.authn;

import com.totalsecurity.sast.cfg.ControlFlowGraph;
import com.totalsecurity.sast.cfg.ControlFlowGraphBuilder;
import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.Definition;
import com.totalsecurity.sast.dataflow.ReachingDefinitionsAnalysis;
import com.totalsecurity.sast.dataflow.VariableSymbolKind;
import com.totalsecurity.sast.interprocedural.ProjectClassEntry;
import com.totalsecurity.sast.interprocedural.ProjectClassIndex;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.MethodKind;
import com.totalsecurity.sast.ir.VariableInfo;
import com.totalsecurity.sast.ir.expression.AssignmentExpression;
import com.totalsecurity.sast.ir.expression.Expression;
import com.totalsecurity.sast.ir.expression.FieldAccessExpression;
import com.totalsecurity.sast.ir.expression.Literal;
import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import com.totalsecurity.sast.ir.expression.ObjectCreationExpression;
import com.totalsecurity.sast.ir.expression.ParenthesizedExpression;
import com.totalsecurity.sast.ir.expression.VariableReference;
import com.totalsecurity.sast.ir.statement.BlockStatement;
import com.totalsecurity.sast.ir.statement.CatchClauseInfo;
import com.totalsecurity.sast.ir.statement.ReturnStatement;
import com.totalsecurity.sast.ir.statement.Statement;
import com.totalsecurity.sast.ir.statement.ThrowStatement;
import com.totalsecurity.sast.ir.statement.TryStatementInfo;
import com.totalsecurity.sast.ir.statement.UnknownStatement;
import com.totalsecurity.sast.ir.statement.VariableDeclarationStatement;
import com.totalsecurity.sast.rule.context.LightweightTypeContext;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Discovers only the audited SHA-256-to-hex refresh-token hasher source shape. */
final class CryptographicRefreshTokenHasherDiscovery {
    Set<String> discover(Collection<JavaFileInfo> files) {
        ProjectClassIndex index = new ProjectClassIndex(files);
        LinkedHashSet<String> verified = new LinkedHashSet<>();
        for (ProjectClassEntry owner : index.uniqueClasses()) {
            if (!Authn11Names.simpleName(owner.qualifiedName()).equals("RefreshTokenHasher")) {
                continue;
            }
            List<MethodInfo> candidates = owner.type().methods().stream()
                    .filter(method -> method.kind() == MethodKind.METHOD)
                    .filter(method -> method.name().equals("hash"))
                    .filter(method -> method.parameters().size() == 1)
                    .toList();
            if (candidates.size() == 1
                    && provesSha256Hex(owner, candidates.getFirst(), index)) {
                verified.add(owner.qualifiedName());
            }
        }
        return Set.copyOf(verified);
    }

    private static boolean provesSha256Hex(
            ProjectClassEntry owner, MethodInfo method, ProjectClassIndex index) {
        LightweightTypeContext types = new LightweightTypeContext(
                owner.file(), index, owner.type());
        if (types.qualifyTypeShape(method.parameters().getFirst().type())
                        .filter("java.lang.String"::equals).isEmpty()
                || method.returnType().flatMap(types::qualifyTypeShape)
                        .filter("java.lang.String"::equals).isEmpty()
                || method.returns().size() != 1
                || method.returns().getFirst().expression().isEmpty()) {
            return false;
        }
        Optional<DataFlowResult> dataFlow = verificationDataFlow(owner, method, types);
        if (dataFlow.isEmpty()) {
            return false;
        }
        Optional<Expression> resolvedReturn = resolve(
                method.returns().getFirst().expression().orElseThrow(), dataFlow.orElseThrow(),
                Collections.newSetFromMap(new IdentityHashMap<>()));
        if (resolvedReturn.isEmpty()) {
            return false;
        }
        Expression returned = resolvedReturn.orElseThrow();
        if (!(returned instanceof MethodCallExpression formatHex)
                || !formatHex.call().methodName().equals("formatHex")
                || formatHex.call().arguments().size() != 1
                || !isStaticFactory(
                        formatHex.call().receiver(), "of", "java.util.HexFormat", types)) {
            return false;
        }
        Optional<Expression> resolvedDigest = resolve(
                formatHex.call().arguments().getFirst(), dataFlow.orElseThrow(),
                Collections.newSetFromMap(new IdentityHashMap<>()));
        if (resolvedDigest.isEmpty()) {
            return false;
        }
        Expression digestValue = resolvedDigest.orElseThrow();
        if (!(digestValue instanceof MethodCallExpression digest)
                || !digest.call().methodName().equals("digest")
                || digest.call().arguments().size() != 1
                || digest.call().receiver().isEmpty()
                || !(digest.call().receiver().orElseThrow() instanceof MethodCallExpression instance)
                || !messageDigestSha256(
                        instance, owner, dataFlow.orElseThrow(), types)) {
            return false;
        }
        Optional<Expression> resolvedBytes = resolve(
                digest.call().arguments().getFirst(), dataFlow.orElseThrow(),
                Collections.newSetFromMap(new IdentityHashMap<>()));
        if (resolvedBytes.isEmpty()) {
            return false;
        }
        Expression bytes = resolvedBytes.orElseThrow();
        if (!(bytes instanceof MethodCallExpression getBytes)
                || !getBytes.call().methodName().equals("getBytes")
                || getBytes.call().arguments().size() > 1
                || getBytes.call().receiver().isEmpty()) {
            return false;
        }
        Optional<Expression> resolvedRaw = resolve(
                getBytes.call().receiver().orElseThrow(), dataFlow.orElseThrow(),
                Collections.newSetFromMap(new IdentityHashMap<>()));
        if (resolvedRaw.isEmpty()) {
            return false;
        }
        Expression raw = resolvedRaw.orElseThrow();
        return raw instanceof VariableReference reference
                && reference.name().equals(method.parameters().getFirst().name());
    }

    private static boolean messageDigestSha256(
            MethodCallExpression instance,
            ProjectClassEntry owner,
            DataFlowResult dataFlow,
            LightweightTypeContext types) {
        if (!instance.call().methodName().equals("getInstance")
                || instance.call().arguments().size() != 1
                || typeReference(instance.call().receiver())
                        .flatMap(types::qualifyType)
                        .filter("java.security.MessageDigest"::equals).isEmpty()) {
            return false;
        }
        Optional<Expression> resolvedAlgorithm = resolve(
                instance.call().arguments().getFirst(), dataFlow,
                Collections.newSetFromMap(new IdentityHashMap<>()));
        if (resolvedAlgorithm.isEmpty()) {
            return false;
        }
        Expression algorithm = resolvedAlgorithm.orElseThrow();
        if (algorithm instanceof VariableReference reference
                && dataFlow.resolvedSymbol(reference).isEmpty()) {
            Optional<Expression> constant = exactStaticFinalStringField(
                    reference.name(), owner, types);
            if (constant.isEmpty()) {
                return false;
            }
            algorithm = constant.orElseThrow();
        } else if (algorithm instanceof FieldAccessExpression field) {
            Optional<String> target = typeReference(field.target()).flatMap(types::qualifyType);
            if (target.filter(owner.qualifiedName()::equals).isEmpty()) {
                return false;
            }
            Optional<Expression> constant = exactStaticFinalStringField(
                    field.fieldName(), owner, types);
            if (constant.isEmpty()) {
                return false;
            }
            algorithm = constant.orElseThrow();
        }
        return algorithm instanceof Literal literal
                && literal.kind().equals("string_literal")
                && unquote(literal.source()).equalsIgnoreCase("SHA-256");
    }

    private static boolean isStaticFactory(
            Optional<Expression> receiver,
            String method,
            String owner,
            LightweightTypeContext types) {
        if (receiver.isEmpty() || !(receiver.orElseThrow() instanceof MethodCallExpression factory)
                || !factory.call().methodName().equals(method)
                || !factory.call().arguments().isEmpty()) {
            return false;
        }
        return typeReference(factory.call().receiver())
                .flatMap(types::qualifyType)
                .filter(owner::equals)
                .isPresent();
    }

    private static Optional<Expression> resolve(
            Expression expression,
            DataFlowResult dataFlow,
            Set<Expression> visited) {
        if (!visited.add(expression)) {
            return Optional.empty();
        }
        if (expression instanceof ParenthesizedExpression parenthesized) {
            return resolve(parenthesized.expression(), dataFlow, visited);
        }
        if (expression instanceof AssignmentExpression assignment) {
            return resolve(assignment.assignment().right(), dataFlow, visited);
        }
        if (expression instanceof VariableReference reference) {
            var symbol = dataFlow.resolvedSymbol(reference);
            if (symbol.isEmpty()) {
                return Optional.of(reference);
            }
            Set<Definition> definitions = dataFlow.reachingDefinitions(reference);
            if (definitions.size() != 1) {
                return Optional.empty();
            }
            Definition definition = definitions.iterator().next();
            if (definition.assignedExpression().isPresent()) {
                return resolve(definition.assignedExpression().orElseThrow(), dataFlow, visited);
            }
            return definition.variable().kind() == VariableSymbolKind.PARAMETER
                    ? Optional.of(reference)
                    : Optional.empty();
        }
        return Optional.of(expression);
    }

    private static Optional<Expression> exactStaticFinalStringField(
            String name, ProjectClassEntry owner, LightweightTypeContext types) {
        List<VariableInfo> fields = owner.type().fields().stream()
                .filter(field -> field.name().equals(name))
                .filter(VariableInfo::staticMember)
                .filter(VariableInfo::finalMember)
                .filter(field -> types.qualifyTypeShape(field.type())
                        .filter("java.lang.String"::equals).isPresent())
                .filter(field -> field.initializer().isPresent())
                .toList();
        return fields.size() == 1 ? fields.getFirst().initializer() : Optional.empty();
    }

    private static Optional<DataFlowResult> verificationDataFlow(
            ProjectClassEntry owner, MethodInfo method, LightweightTypeContext types) {
        Optional<DataFlowResult> direct = analyze(method);
        if (direct.isPresent()) {
            return direct;
        }
        return projectedTryMethod(owner, method, types)
                .flatMap(CryptographicRefreshTokenHasherDiscovery::analyze);
    }

    private static Optional<DataFlowResult> analyze(MethodInfo method) {
        try {
            ControlFlowGraph graph = new ControlFlowGraphBuilder().build(method);
            DataFlowResult result = new ReachingDefinitionsAnalysis().analyze(graph);
            return graph.unsupportedControlFlow().isEmpty()
                            && result.unsupportedDataFlow().isEmpty()
                    ? Optional.of(result)
                    : Optional.empty();
        } catch (RuntimeException exception) {
            return Optional.empty();
        }
    }

    /**
     * The audited hasher wraps one straight-line successful return in try/catch. The general CFG
     * intentionally retains try as unsupported, so projection is permitted only when every direct
     * statement and initializer belongs to the audited straight-line subset. Unknown structure,
     * side-effect-only calls, mutation, resources, finally blocks and non-throwing catches fail
     * closed.
     */
    private static Optional<MethodInfo> projectedTryMethod(
            ProjectClassEntry owner, MethodInfo method, LightweightTypeContext types) {
        if (method.body().isEmpty()
                || method.body().orElseThrow().statements().size() != 1
                || !(method.body().orElseThrow().statements().getFirst()
                        instanceof UnknownStatement unknown)
                || !unknown.syntaxKind().equals("try_statement")
                || unknown.tryStatement().isEmpty()
                || !method.assignments().isEmpty()
                || method.returns().size() != 1
                || method.returns().getFirst().expression().isEmpty()) {
            return Optional.empty();
        }

        TryStatementInfo tryStatement = unknown.tryStatement().orElseThrow();
        List<Statement> statements = tryStatement.body().statements();
        ProjectionTypeEnvironment environment = projectionTypeEnvironment(owner, method, types);
        if (tryStatement.resourcesPresent()
                || tryStatement.finallyBlock().isPresent()
                || tryStatement.catches().isEmpty()
                || tryStatement.catches().stream()
                        .anyMatch(catchClause -> !isSimpleThrowingCatch(catchClause, types))
                || statements.isEmpty()
                || !(statements.getLast() instanceof ReturnStatement returned)
                || returned.expression().isEmpty()
                || statements.stream().filter(ReturnStatement.class::isInstance).count() != 1
                || statements.subList(0, statements.size() - 1).stream()
                        .anyMatch(statement ->
                                !addSupportedTryLocals(statement, types, environment))) {
            return Optional.empty();
        }

        List<VariableInfo> projectedLocals = statements.subList(0, statements.size() - 1).stream()
                .map(VariableDeclarationStatement.class::cast)
                .flatMap(declaration -> declaration.variables().stream())
                .toList();
        if (projectedLocals.stream().map(VariableInfo::name).distinct().count()
                        != projectedLocals.size()
                || method.localVariables().size() != projectedLocals.size()) {
            return Optional.empty();
        }

        List<Statement> projectedStatements = new ArrayList<>(
                statements.subList(0, statements.size() - 1));
        var originalReturn = method.returns().getFirst();
        projectedStatements.add(new ReturnStatement(
                originalReturn.expression(), originalReturn.location()));
        BlockStatement body = new BlockStatement(
                projectedStatements, tryStatement.body().location());
        return Optional.of(new MethodInfo(
                method.kind(), method.name(), method.returnType(), method.typeParameters(),
                method.annotations(), method.parameters(), projectedLocals,
                method.assignments(), method.methodCalls(), method.returns(), Optional.of(body),
                method.location()));
    }

    private static boolean addSupportedTryLocals(
            Statement statement,
            LightweightTypeContext types,
            ProjectionTypeEnvironment environment) {
        if (!(statement instanceof VariableDeclarationStatement declaration)
                || declaration.variables().isEmpty()) {
            return false;
        }
        for (VariableInfo variable : declaration.variables()) {
            if (variable.initializer().isEmpty()
                    || !isSupportedInitializer(
                            variable.initializer().orElseThrow(), types, environment)) {
                return false;
            }
            environment.values().put(
                    variable.name(), types.qualifyTypeShape(variable.type()));
        }
        return true;
    }

    private static boolean isSupportedInitializer(
            Expression expression,
            LightweightTypeContext types,
            ProjectionTypeEnvironment environment) {
        if (expression instanceof ParenthesizedExpression parenthesized) {
            return isSupportedInitializer(parenthesized.expression(), types, environment);
        }
        if (expression instanceof Literal || expression instanceof VariableReference) {
            return true;
        }
        if (expression instanceof FieldAccessExpression field) {
            return isSideEffectFreeValue(field.target());
        }
        if (!(expression instanceof MethodCallExpression call)) {
            return false;
        }
        return switch (call.call().methodName()) {
            case "getBytes" -> isSupportedGetBytes(call, types, environment);
            case "getInstance" -> isSupportedGetInstance(call, types);
            case "digest" -> isSupportedDigest(call, types, environment);
            default -> false;
        };
    }

    private static boolean isSupportedGetBytes(
            MethodCallExpression call,
            LightweightTypeContext types,
            ProjectionTypeEnvironment environment) {
        if (call.call().receiver().isEmpty()
                || !isProvenStringReceiver(call.call().receiver().orElseThrow(), environment)
                || call.call().arguments().size() > 1) {
            return false;
        }
        return call.call().arguments().isEmpty()
                || isUtf8Charset(call.call().arguments().getFirst(), types);
    }

    private static boolean isSupportedGetInstance(
            MethodCallExpression call, LightweightTypeContext types) {
        return call.call().arguments().size() == 1
                && typeReference(call.call().receiver())
                        .flatMap(types::qualifyType)
                        .filter("java.security.MessageDigest"::equals)
                        .isPresent()
                && isSideEffectFreeValue(call.call().arguments().getFirst());
    }

    private static boolean isSupportedDigest(
            MethodCallExpression call,
            LightweightTypeContext types,
            ProjectionTypeEnvironment environment) {
        if (call.call().receiver().isEmpty()
                || !(call.call().receiver().orElseThrow() instanceof MethodCallExpression instance)
                || !isSupportedGetInstance(instance, types)
                || call.call().arguments().size() != 1) {
            return false;
        }
        Expression input = call.call().arguments().getFirst();
        return input instanceof VariableReference
                || input instanceof MethodCallExpression getBytes
                        && getBytes.call().methodName().equals("getBytes")
                        && isSupportedGetBytes(getBytes, types, environment);
    }

    private static ProjectionTypeEnvironment projectionTypeEnvironment(
            ProjectClassEntry owner, MethodInfo method, LightweightTypeContext types) {
        LinkedHashMap<String, Optional<String>> fields = new LinkedHashMap<>();
        owner.type().fields().forEach(field -> mergeDeclaredType(
                fields, field.name(), types.qualifyTypeShape(field.type())));
        LinkedHashMap<String, Optional<String>> values = new LinkedHashMap<>(fields);
        method.parameters().forEach(parameter -> values.put(
                parameter.name(), types.qualifyTypeShape(parameter.type())));
        return new ProjectionTypeEnvironment(values, fields);
    }

    private static void mergeDeclaredType(
            Map<String, Optional<String>> types, String name, Optional<String> declaredType) {
        if (types.containsKey(name)) {
            types.put(name, Optional.empty());
        } else {
            types.put(name, declaredType);
        }
    }

    private static boolean isProvenStringReceiver(
            Expression expression, ProjectionTypeEnvironment environment) {
        if (expression instanceof ParenthesizedExpression parenthesized) {
            return isProvenStringReceiver(parenthesized.expression(), environment);
        }
        if (expression instanceof Literal literal) {
            return literal.kind().equals("string_literal");
        }
        if (expression instanceof VariableReference reference) {
            return environment.values().getOrDefault(reference.name(), Optional.empty())
                    .filter("java.lang.String"::equals)
                    .isPresent();
        }
        if (expression instanceof FieldAccessExpression field
                && field.target() instanceof VariableReference target
                && target.name().equals("this")) {
            return environment.fields().getOrDefault(field.fieldName(), Optional.empty())
                    .filter("java.lang.String"::equals)
                    .isPresent();
        }
        return false;
    }

    private static boolean isUtf8Charset(
            Expression expression, LightweightTypeContext types) {
        if (!(expression instanceof FieldAccessExpression field)
                || !field.fieldName().equals("UTF_8")) {
            return false;
        }
        return typeReference(field.target())
                .flatMap(types::qualifyType)
                .filter("java.nio.charset.StandardCharsets"::equals)
                .isPresent();
    }

    private static boolean isSideEffectFreeValue(Expression expression) {
        if (expression instanceof ParenthesizedExpression parenthesized) {
            return isSideEffectFreeValue(parenthesized.expression());
        }
        if (expression instanceof VariableReference || expression instanceof Literal) {
            return true;
        }
        return expression instanceof FieldAccessExpression field
                && isSideEffectFreeValue(field.target());
    }

    private static boolean isSimpleThrowingCatch(
            CatchClauseInfo catchClause, LightweightTypeContext types) {
        if (catchClause.body().statements().size() != 1
                || !(catchClause.body().statements().getFirst() instanceof ThrowStatement thrown)
                || !(thrown.expression() instanceof ObjectCreationExpression creation)
                || !isExactIllegalStateException(creation.typeName(), types)) {
            return false;
        }
        if (creation.arguments().size() == 1) {
            return creation.arguments().getFirst() instanceof VariableReference;
        }
        return creation.arguments().size() == 2
                && isSupportedCatchMessage(creation.arguments().getFirst())
                && creation.arguments().get(1) instanceof VariableReference;
    }

    private static boolean isSupportedCatchMessage(Expression expression) {
        if (expression instanceof Literal) {
            return true;
        }
        if (!(expression instanceof MethodCallExpression call)
                || !call.call().methodName().equals("formatted")
                || call.call().receiver().isEmpty()
                || !(call.call().receiver().orElseThrow() instanceof Literal)) {
            return false;
        }
        return call.call().arguments().stream()
                .allMatch(CryptographicRefreshTokenHasherDiscovery::isSideEffectFreeValue);
    }

    private static boolean isExactIllegalStateException(
            String declaredType, LightweightTypeContext types) {
        if (declaredType.equals("java.lang.IllegalStateException")) {
            return true;
        }
        if (!declaredType.equals("IllegalStateException")) {
            return false;
        }
        Optional<String> qualified = types.qualifyType(declaredType);
        if (qualified.isPresent()) {
            return qualified.filter("java.lang.IllegalStateException"::equals).isPresent();
        }
        return types.file().imports().stream()
                .filter(imported -> !imported.startsWith("static "))
                .noneMatch(imported -> imported.endsWith(".*")
                        || imported.endsWith(".IllegalStateException"));
    }

    private static Optional<String> typeReference(Optional<Expression> receiver) {
        return receiver.flatMap(CryptographicRefreshTokenHasherDiscovery::typeReference);
    }

    private static Optional<String> typeReference(Expression expression) {
        if (expression instanceof VariableReference reference) {
            return Optional.of(reference.name());
        }
        if (expression instanceof FieldAccessExpression field) {
            return typeReference(field.target()).map(owner -> owner + "." + field.fieldName());
        }
        return Optional.empty();
    }

    private static String unquote(String source) {
        return source.length() >= 2 && source.startsWith("\"") && source.endsWith("\"")
                ? source.substring(1, source.length() - 1)
                : source;
    }

    private record ProjectionTypeEnvironment(
            Map<String, Optional<String>> values,
            Map<String, Optional<String>> fields) {
    }
}
