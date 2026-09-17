package com.totalsecurity.sast.rule.context;

import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.expression.Expression;
import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** A lightweight, Tree-sitter-independent view of one concrete method-call occurrence. */
public record CallSiteContext(
        JavaFileInfo file,
        ClassInfo enclosingClass,
        MethodInfo enclosingMethod,
        MethodCallExpression call,
        Optional<Expression> receiver,
        Optional<String> receiverDeclaredType,
        Optional<String> receiverQualifiedType,
        boolean receiverBoundToValue,
        String methodName,
        List<Expression> arguments,
        List<Optional<String>> argumentQualifiedTypes,
        SourceLocation location,
        LightweightTypeContext types) {
    public CallSiteContext {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(enclosingClass, "enclosingClass");
        Objects.requireNonNull(enclosingMethod, "enclosingMethod");
        Objects.requireNonNull(call, "call");
        receiver = Objects.requireNonNull(receiver, "receiver");
        receiverDeclaredType = Objects.requireNonNull(receiverDeclaredType, "receiverDeclaredType");
        receiverQualifiedType = Objects.requireNonNull(receiverQualifiedType, "receiverQualifiedType");
        Objects.requireNonNull(methodName, "methodName");
        arguments = List.copyOf(arguments);
        argumentQualifiedTypes = List.copyOf(argumentQualifiedTypes);
        if (argumentQualifiedTypes.size() != arguments.size()) {
            throw new IllegalArgumentException("Argument types must align with argument occurrences");
        }
        Objects.requireNonNull(location, "location");
        Objects.requireNonNull(types, "types");
    }

    public int argumentCount() {
        return arguments.size();
    }

    public boolean argumentHasType(int index, String qualifiedType) {
        return argumentQualifiedTypes.get(index).filter(qualifiedType::equals).isPresent();
    }
}
