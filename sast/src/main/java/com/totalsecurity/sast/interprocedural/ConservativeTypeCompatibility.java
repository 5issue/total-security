package com.totalsecurity.sast.interprocedural;

import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.TypeParameterInfo;
import com.totalsecurity.sast.rule.context.LightweightTypeContext;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Deliberately small Java invocation-conversion subset backed only by local IR facts. */
final class ConservativeTypeCompatibility {
    enum Match {
        COMPATIBLE,
        INCOMPATIBLE,
        UNKNOWN
    }

    private static final Map<String, String> PRIMITIVE_TO_WRAPPER = Map.of(
            "boolean", "java.lang.Boolean",
            "byte", "java.lang.Byte",
            "short", "java.lang.Short",
            "char", "java.lang.Character",
            "int", "java.lang.Integer",
            "long", "java.lang.Long",
            "float", "java.lang.Float",
            "double", "java.lang.Double");
    private static final Map<String, Set<String>> PRIMITIVE_WIDENING = Map.of(
            "byte", Set.of("short", "int", "long", "float", "double"),
            "short", Set.of("int", "long", "float", "double"),
            "char", Set.of("int", "long", "float", "double"),
            "int", Set.of("long", "float", "double"),
            "long", Set.of("float", "double"),
            "float", Set.of("double"));

    private final ProjectClassIndex project;

    ConservativeTypeCompatibility(ProjectClassIndex project) {
        this.project = Objects.requireNonNull(project, "project");
    }

    boolean isExact(
            String argument,
            MethodInfo method,
            int parameterIndex,
            LightweightTypeContext targetTypes) {
        if (typeParameterUse(method, method.parameters().get(parameterIndex).type()).isPresent()) {
            return false;
        }
        return targetTypes.qualifyTypeShape(method.parameters().get(parameterIndex).type())
                .filter(argument::equals)
                .isPresent();
    }

    Match match(
            String argument,
            MethodInfo method,
            int parameterIndex,
            LightweightTypeContext targetTypes) {
        String declaredParameter = method.parameters().get(parameterIndex).type();
        Optional<TypeParameterUse> typeParameter = typeParameterUse(method, declaredParameter);
        if (typeParameter.isPresent()) {
            return matchTypeParameterUse(argument, typeParameter.orElseThrow(), targetTypes);
        }
        Optional<String> parameter = targetTypes.qualifyTypeShape(declaredParameter);
        return parameter.map(value -> matchQualified(argument, value)).orElse(Match.UNKNOWN);
    }

    private Match matchTypeParameterUse(
            String argument,
            TypeParameterUse use,
            LightweightTypeContext targetTypes) {
        if (use.arrayDimensions() == 0) {
            return matchTypeParameter(argument, use.parameter(), targetTypes);
        }
        TypeShape argumentShape = typeShape(argument);
        if (argumentShape.varargs() || argumentShape.arrayDimensions() != use.arrayDimensions()) {
            return Match.INCOMPATIBLE;
        }
        if (isPrimitive(argumentShape.componentType())) {
            return Match.INCOMPATIBLE;
        }
        return matchTypeParameter(argumentShape.componentType(), use.parameter(), targetTypes);
    }

    private Match matchTypeParameter(
            String argument,
            TypeParameterInfo parameter,
            LightweightTypeContext targetTypes) {
        if (parameter.upperBounds().isEmpty()) {
            return Match.COMPATIBLE;
        }
        boolean unknown = false;
        for (String bound : parameter.upperBounds()) {
            Optional<String> qualified = targetTypes.qualifyTypeShape(bound);
            if (qualified.isEmpty()) {
                unknown = true;
                continue;
            }
            Match boundMatch = matchQualified(argument, qualified.orElseThrow());
            if (boundMatch == Match.INCOMPATIBLE) {
                return Match.INCOMPATIBLE;
            }
            if (boundMatch == Match.UNKNOWN) {
                unknown = true;
            }
        }
        return unknown ? Match.UNKNOWN : Match.COMPATIBLE;
    }

    private Match matchQualified(String argument, String parameter) {
        if (argument.equals(parameter)) {
            return Match.COMPATIBLE;
        }
        if (parameter.equals("java.lang.Object") && isReferenceType(argument)) {
            return Match.COMPATIBLE;
        }
        if (isBoxingPair(argument, parameter)) {
            return Match.COMPATIBLE;
        }
        if (isPrimitive(argument) && isPrimitive(parameter)) {
            return PRIMITIVE_WIDENING.getOrDefault(argument, Set.of()).contains(parameter)
                    ? Match.COMPATIBLE
                    : Match.INCOMPATIBLE;
        }
        if (isReferenceType(argument) && isReferenceType(parameter)
                && project.isDeclaredSubtypeOf(argument, parameter)) {
            return Match.COMPATIBLE;
        }
        return Match.INCOMPATIBLE;
    }

    private static Optional<TypeParameterUse> typeParameterUse(MethodInfo method, String declared) {
        TypeShape shape = typeShape(declared);
        return method.typeParameters().stream()
                .filter(parameter -> parameter.name().equals(shape.componentType()))
                .findFirst()
                .map(parameter -> new TypeParameterUse(parameter, shape.arrayDimensions()));
    }

    private static boolean isBoxingPair(String left, String right) {
        return PRIMITIVE_TO_WRAPPER.getOrDefault(left, "").equals(right)
                || PRIMITIVE_TO_WRAPPER.getOrDefault(right, "").equals(left);
    }

    private static boolean isReferenceType(String type) {
        return type.endsWith("[]") || !isPrimitive(type);
    }

    private static boolean isPrimitive(String type) {
        return switch (type) {
            case "boolean", "byte", "short", "char", "int", "long", "float", "double" -> true;
            default -> false;
        };
    }

    private static TypeShape typeShape(String declared) {
        String value = declared.trim();
        int generic = value.indexOf('<');
        if (generic >= 0) {
            value = value.substring(0, generic);
        }
        boolean varargs = value.endsWith("...");
        if (varargs) {
            value = value.substring(0, value.length() - 3).trim();
        }
        int dimensions = varargs ? 1 : 0;
        while (value.endsWith("[]")) {
            value = value.substring(0, value.length() - 2).trim();
            dimensions++;
        }
        return new TypeShape(value, dimensions, varargs);
    }

    private record TypeParameterUse(TypeParameterInfo parameter, int arrayDimensions) {}

    private record TypeShape(String componentType, int arrayDimensions, boolean varargs) {}
}
