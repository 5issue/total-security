package com.totalsecurity.sast.ir;

import com.totalsecurity.sast.ir.statement.BlockStatement;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public record MethodInfo(
        MethodKind kind,
        String name,
        Optional<String> returnType,
        List<TypeParameterInfo> typeParameters,
        List<AnnotationInfo> annotations,
        List<ParameterInfo> parameters,
        List<VariableInfo> localVariables,
        List<AssignmentInfo> assignments,
        List<MethodCallInfo> methodCalls,
        List<ReturnInfo> returns,
        Optional<BlockStatement> body,
        SourceLocation location) {
    public MethodInfo {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(name, "name");
        returnType = Objects.requireNonNull(returnType, "returnType");
        typeParameters = List.copyOf(typeParameters);
        annotations = List.copyOf(annotations);
        parameters = List.copyOf(parameters);
        localVariables = List.copyOf(localVariables);
        assignments = List.copyOf(assignments);
        methodCalls = List.copyOf(methodCalls);
        returns = List.copyOf(returns);
        body = Objects.requireNonNull(body, "body");
        Objects.requireNonNull(location, "location");
    }

    /** Compatibility constructor for methods without extracted type-parameter metadata. */
    public MethodInfo(
            MethodKind kind,
            String name,
            Optional<String> returnType,
            List<AnnotationInfo> annotations,
            List<ParameterInfo> parameters,
            List<VariableInfo> localVariables,
            List<AssignmentInfo> assignments,
            List<MethodCallInfo> methodCalls,
            List<ReturnInfo> returns,
            Optional<BlockStatement> body,
            SourceLocation location) {
        this(kind, name, returnType, List.of(), annotations, parameters, localVariables,
                assignments, methodCalls, returns, body, location);
    }
}
