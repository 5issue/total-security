package com.totalsecurity.sast.detector.authn;

import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.Definition;
import com.totalsecurity.sast.interprocedural.ProjectClassEntry;
import com.totalsecurity.sast.interprocedural.ProjectClassIndex;
import com.totalsecurity.sast.ir.AssignmentInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.MethodKind;
import com.totalsecurity.sast.ir.ParameterInfo;
import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.TypeKind;
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
import com.totalsecurity.sast.rule.context.CallSiteContextResolver;
import com.totalsecurity.sast.rule.context.LightweightTypeContext;
import com.totalsecurity.sast.taint.TaintAnalysisResult;
import com.totalsecurity.sast.taint.TaintState;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Conservative extraction of values actually stored in one broker message payload. */
final class Svc05PayloadInspector {
    private static final Set<String> PROVEN_NON_TOKEN_SCALARS = Set.of(
            "boolean", "byte", "short", "char", "int", "long", "float", "double",
            "java.lang.Boolean", "java.lang.Byte", "java.lang.Short",
            "java.lang.Character", "java.lang.Integer", "java.lang.Long",
            "java.lang.Float", "java.lang.Double", "java.math.BigInteger",
            "java.math.BigDecimal", "java.util.UUID", "java.time.Instant",
            "java.time.LocalDate", "java.time.LocalDateTime", "java.time.Duration");

    PayloadInspection inspect(
            Expression payload,
            CallSiteContextResolver calls,
            DataFlowResult dataFlow,
            TaintAnalysisResult taint,
            ProjectClassIndex index) {
        return inspect(payload, calls, dataFlow, taint, index,
                Collections.newSetFromMap(new IdentityHashMap<>()));
    }

    private PayloadInspection inspect(
            Expression expression,
            CallSiteContextResolver calls,
            DataFlowResult dataFlow,
            TaintAnalysisResult taint,
            ProjectClassIndex index,
            Set<Expression> visited) {
        if (!visited.add(expression)) {
            return unsupported("Cyclic payload expression", expression.location());
        }
        if (expression instanceof ParenthesizedExpression parenthesized) {
            return inspect(parenthesized.expression(), calls, dataFlow, taint, index, visited);
        }
        if (expression instanceof AssignmentExpression assignment) {
            return inspect(assignment.assignment().right(), calls, dataFlow, taint, index, visited);
        }
        if (expression instanceof VariableReference reference) {
            List<Definition> definitions = dataFlow.reachingDefinitions(reference).stream()
                    .filter(definition -> definition.assignedExpression().isPresent())
                    .toList();
            if (definitions.isEmpty()) {
                return directValue(expression, calls, taint, index);
            }
            PayloadInspection result = PayloadInspection.empty();
            for (Definition definition : definitions) {
                result = result.merge(inspect(
                        definition.assignedExpression().orElseThrow(), calls, dataFlow,
                        taint, index, visited));
            }
            return result;
        }
        if (expression instanceof ObjectCreationExpression creation) {
            return objectCreation(creation, calls, dataFlow, taint, index, visited);
        }
        if (expression instanceof MethodCallExpression call) {
            Optional<PayloadInspection> serialization = serializedPayload(
                    call, calls, dataFlow, taint, index, visited);
            if (serialization.isPresent()) {
                return serialization.orElseThrow();
            }
            Optional<PayloadInspection> builder = builderPayload(
                    call, calls, dataFlow, taint, index, visited);
            if (builder.isPresent()) {
                return builder.orElseThrow();
            }
            return directValue(expression, calls, taint, index);
        }
        if (expression instanceof Literal
                || expression instanceof BinaryExpression
                || expression instanceof FieldAccessExpression) {
            return directValue(expression, calls, taint, index);
        }
        if (expression instanceof UnknownExpression unknown) {
            return unsupported(
                    "Unsupported broker payload expression " + unknown.syntaxKind(),
                    expression.location());
        }
        return unsupported("Unsupported broker payload expression", expression.location());
    }

    private PayloadInspection objectCreation(
            ObjectCreationExpression creation,
            CallSiteContextResolver calls,
            DataFlowResult dataFlow,
            TaintAnalysisResult taint,
            ProjectClassIndex index,
            Set<Expression> visited) {
        Optional<String> qualified = calls.types().qualifyType(creation.typeName());
        if (qualified.filter("java.lang.String"::equals).isPresent()) {
            if (creation.arguments().isEmpty()) {
                return PayloadInspection.empty();
            }
            PayloadInspection result = PayloadInspection.empty();
            for (Expression argument : creation.arguments()) {
                result = result.merge(inspect(
                        argument, calls, dataFlow, taint, index, visited));
            }
            return result;
        }
        Optional<ProjectClassEntry> payloadType = qualified.flatMap(index::uniqueClass);
        if (payloadType.isEmpty()) {
            return unsupported(
                    "Broker payload object type is not an exact unique project type",
                    creation.location());
        }
        ProjectClassEntry target = payloadType.orElseThrow();
        if (target.type().kind() == TypeKind.RECORD) {
            if (target.type().recordComponents().size() != creation.arguments().size()) {
                return unsupported(
                        "Record payload constructor arity does not match record components",
                        creation.location());
            }
            return inspectArguments(
                    creation.arguments(), calls, dataFlow, taint, index, visited);
        }
        List<MethodInfo> constructors = target.type().methods().stream()
                .filter(method -> method.kind() == MethodKind.CONSTRUCTOR)
                .filter(method -> method.parameters().size() == creation.arguments().size())
                .toList();
        if (constructors.size() != 1) {
            return unsupported(
                    "Broker payload constructor target is absent or ambiguous",
                    creation.location());
        }
        MethodInfo constructor = constructors.getFirst();
        Map<String, String> mappings = constructorParameterFields(constructor, target);
        PayloadInspection result = PayloadInspection.empty();
        boolean incomplete = false;
        for (int indexOfArgument = 0;
                indexOfArgument < constructor.parameters().size();
                indexOfArgument++) {
            ParameterInfo parameter = constructor.parameters().get(indexOfArgument);
            if (!mappings.containsKey(parameter.name())) {
                incomplete = true;
                continue;
            }
            result = result.merge(inspect(
                    creation.arguments().get(indexOfArgument), calls, dataFlow,
                    taint, index, visited));
        }
        if (incomplete) {
            result = result.withUnsupported(new UnsupportedSvc05Flow(
                    "Constructor payload mapping is incomplete, discarded, or overwritten",
                    creation.location()));
        }
        return result;
    }

    private Optional<PayloadInspection> serializedPayload(
            MethodCallExpression expression,
            CallSiteContextResolver calls,
            DataFlowResult dataFlow,
            TaintAnalysisResult taint,
            ProjectClassIndex index,
            Set<Expression> visited) {
        var call = calls.resolve(expression);
        if (call.receiverQualifiedType()
                        .filter("com.fasterxml.jackson.databind.ObjectMapper"::equals).isEmpty()
                || !call.methodName().equals("writeValueAsString")
                || call.argumentCount() != 1) {
            return Optional.empty();
        }
        return Optional.of(inspect(
                call.arguments().getFirst(), calls, dataFlow, taint, index, visited));
    }

    private Optional<PayloadInspection> builderPayload(
            MethodCallExpression expression,
            CallSiteContextResolver calls,
            DataFlowResult dataFlow,
            TaintAnalysisResult taint,
            ProjectClassIndex index,
            Set<Expression> visited) {
        if (!expression.call().methodName().equals("build")
                || !expression.call().arguments().isEmpty()
                || expression.call().receiver().isEmpty()) {
            return Optional.empty();
        }
        LinkedHashMap<String, Expression> setterValues = new LinkedHashMap<>();
        Expression cursor = expression.call().receiver().orElseThrow();
        while (cursor instanceof MethodCallExpression call) {
            if (call.call().methodName().equals("builder")
                    && call.call().arguments().isEmpty()) {
                Optional<ProjectClassEntry> target = calls.resolve(call)
                        .receiverQualifiedType().flatMap(index::uniqueClass);
                if (target.isEmpty()) {
                    return Optional.of(unsupported(
                            "Lombok builder payload owner is not an exact unique project type",
                            expression.location()));
                }
                Map<String, String> supportedSetters = lombokBuilderSetters(
                        target.orElseThrow(), index);
                if (supportedSetters.isEmpty()
                        || setterValues.keySet().stream()
                                .anyMatch(setter -> !supportedSetters.containsKey(setter))) {
                    return Optional.of(unsupported(
                            "Broker payload builder is not an exact supported Lombok @Builder shape",
                            expression.location()));
                }
                PayloadInspection result = PayloadInspection.empty();
                for (Expression value : setterValues.values()) {
                    result = result.merge(inspect(
                            value, calls, dataFlow, taint, index, visited));
                }
                return Optional.of(result);
            }
            if (call.call().arguments().size() != 1 || call.call().receiver().isEmpty()) {
                return Optional.of(unsupported(
                        "Broker payload builder chain contains an unsupported call",
                        call.location()));
            }
            setterValues.putIfAbsent(
                    call.call().methodName(), call.call().arguments().getFirst());
            cursor = call.call().receiver().orElseThrow();
        }
        return Optional.of(unsupported(
                "Broker payload build call has no exact Lombok builder factory",
                expression.location()));
    }

    private PayloadInspection directValue(
            Expression expression,
            CallSiteContextResolver calls,
            TaintAnalysisResult taint,
            ProjectClassIndex index) {
        var value = taint.taintOf(expression);
        if (value.state() == TaintState.TAINTED) {
            return PayloadInspection.of(expression);
        }
        Optional<String> type = calls.qualifiedTypeShapeOf(expression);
        if (type.filter(Svc05PayloadInspector::isRawCarrier).isPresent()) {
            return value.state() == TaintState.UNKNOWN
                    ? unsupported("Broker payload raw-value taint is UNKNOWN", expression.location())
                    : PayloadInspection.of(expression);
        }
        if (type.filter(PROVEN_NON_TOKEN_SCALARS::contains).isPresent()
                || type.flatMap(index::uniqueClass)
                        .filter(entry -> entry.type().kind() == TypeKind.ENUM).isPresent()) {
            return PayloadInspection.empty();
        }
        if (value.state() == TaintState.UNKNOWN) {
            return unsupported("Broker payload value taint is UNKNOWN", expression.location());
        }
        return unsupported(
                "Broker payload object mapping is not source-proven", expression.location());
    }

    private PayloadInspection inspectArguments(
            List<Expression> arguments,
            CallSiteContextResolver calls,
            DataFlowResult dataFlow,
            TaintAnalysisResult taint,
            ProjectClassIndex index,
            Set<Expression> visited) {
        PayloadInspection result = PayloadInspection.empty();
        for (Expression argument : arguments) {
            result = result.merge(inspect(argument, calls, dataFlow, taint, index, visited));
        }
        return result;
    }

    private static boolean isRawCarrier(String type) {
        return type.equals("java.lang.String")
                || type.equals("byte[]")
                || type.equals("java.lang.Byte[]")
                || type.equals("char[]")
                || type.equals("java.lang.Character[]");
    }

    private static Map<String, String> lombokBuilderSetters(
            ProjectClassEntry target, ProjectClassIndex index) {
        LightweightTypeContext types = new LightweightTypeContext(
                target.file(), index, target.type());
        List<MethodInfo> builders = target.type().methods().stream()
                .filter(method -> method.kind() == MethodKind.CONSTRUCTOR)
                .filter(method -> method.annotations().stream().anyMatch(annotation ->
                        annotation.arguments().isEmpty()
                                && types.annotationMatches(annotation.name(), "lombok.Builder")))
                .toList();
        if (builders.size() != 1) {
            return Map.of();
        }
        Map<String, String> mappings = constructorParameterFields(builders.getFirst(), target);
        return mappings.size() == builders.getFirst().parameters().size()
                ? mappings
                : Map.of();
    }

    private static Map<String, String> constructorParameterFields(
            MethodInfo constructor, ProjectClassEntry target) {
        Set<String> instanceFields = target.type().fields().stream()
                .filter(field -> !field.staticMember())
                .map(field -> field.name())
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        Map<String, List<AssignmentInfo>> byField = new LinkedHashMap<>();
        for (AssignmentInfo assignment : constructor.assignments()) {
            exactThisField(assignment.left())
                    .filter(instanceFields::contains)
                    .ifPresent(field -> byField
                            .computeIfAbsent(field, ignored -> new ArrayList<>())
                            .add(assignment));
        }
        Set<String> parameters = constructor.parameters().stream()
                .map(ParameterInfo::name)
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        LinkedHashMap<String, String> result = new LinkedHashMap<>();
        byField.forEach((field, assignments) -> {
            if (assignments.size() != 1 || !assignments.getFirst().operator().equals("=")) {
                return;
            }
            exactVariable(assignments.getFirst().right())
                    .filter(parameters::contains)
                    .ifPresent(parameter -> result.put(parameter, field));
        });
        return Map.copyOf(result);
    }

    private static Optional<String> exactThisField(Expression expression) {
        if (expression instanceof ParenthesizedExpression parenthesized) {
            return exactThisField(parenthesized.expression());
        }
        if (expression instanceof FieldAccessExpression field
                && field.target() instanceof VariableReference target
                && target.name().equals("this")) {
            return Optional.of(field.fieldName());
        }
        return Optional.empty();
    }

    private static Optional<String> exactVariable(Expression expression) {
        if (expression instanceof ParenthesizedExpression parenthesized) {
            return exactVariable(parenthesized.expression());
        }
        return expression instanceof VariableReference reference
                ? Optional.of(reference.name())
                : Optional.empty();
    }

    private static PayloadInspection unsupported(String reason, SourceLocation location) {
        return new PayloadInspection(
                List.of(), List.of(new UnsupportedSvc05Flow(reason, location)));
    }

    record PayloadInspection(
            List<Expression> values,
            List<UnsupportedSvc05Flow> unsupported) {
        PayloadInspection {
            values = List.copyOf(new LinkedHashSet<>(values));
            unsupported = List.copyOf(new LinkedHashSet<>(unsupported));
        }

        static PayloadInspection empty() {
            return new PayloadInspection(List.of(), List.of());
        }

        static PayloadInspection of(Expression expression) {
            return new PayloadInspection(List.of(expression), List.of());
        }

        PayloadInspection merge(PayloadInspection other) {
            List<Expression> mergedValues = new ArrayList<>(values);
            mergedValues.addAll(other.values);
            List<UnsupportedSvc05Flow> mergedUnsupported = new ArrayList<>(unsupported);
            mergedUnsupported.addAll(other.unsupported);
            return new PayloadInspection(mergedValues, mergedUnsupported);
        }

        PayloadInspection withUnsupported(UnsupportedSvc05Flow item) {
            List<UnsupportedSvc05Flow> merged = new ArrayList<>(unsupported);
            merged.add(item);
            return new PayloadInspection(values, merged);
        }
    }
}
