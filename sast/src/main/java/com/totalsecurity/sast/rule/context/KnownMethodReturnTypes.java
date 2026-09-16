package com.totalsecurity.sast.rule.context;

import java.util.List;
import java.util.Optional;

/** Small allowlist of exact library signatures whose return types are safe to infer. */
public final class KnownMethodReturnTypes {
    private KnownMethodReturnTypes() {}

    public static Optional<KnownMethod> match(
            String receiverQualifiedType,
            String methodName,
            List<Optional<String>> argumentQualifiedTypes) {
        int arity = argumentQualifiedTypes.size();
        if (receiverQualifiedType.equals("java.lang.Runtime")
                && methodName.equals("getRuntime")
                && arity == 0) {
            return Optional.of(KnownMethod.RUNTIME_GET_RUNTIME);
        }
        if ((receiverQualifiedType.equals("java.nio.file.Path") && methodName.equals("of")
                        || receiverQualifiedType.equals("java.nio.file.Paths") && methodName.equals("get"))
                && arity >= 1
                && allHaveType(argumentQualifiedTypes, "java.lang.String")) {
            return Optional.of(KnownMethod.PATH_FACTORY);
        }
        if (receiverQualifiedType.equals("java.nio.file.Path")
                && methodName.equals("resolve")
                && arity == 1
                && (hasType(argumentQualifiedTypes, 0, "java.lang.String")
                        || hasType(argumentQualifiedTypes, 0, "java.nio.file.Path"))) {
            return Optional.of(KnownMethod.PATH_RESOLVE);
        }
        if (receiverQualifiedType.equals("java.nio.file.Path")
                && (methodName.equals("normalize") || methodName.equals("toAbsolutePath"))
                && arity == 0) {
            return Optional.of(KnownMethod.PATH_RECEIVER_TRANSFORM);
        }
        return Optional.empty();
    }

    private static boolean hasType(
            List<Optional<String>> argumentTypes, int index, String expectedType) {
        return argumentTypes.get(index).filter(expectedType::equals).isPresent();
    }

    private static boolean allHaveType(
            List<Optional<String>> argumentTypes, String expectedType) {
        return argumentTypes.stream()
                .allMatch(argumentType -> argumentType.filter(expectedType::equals).isPresent());
    }

    public enum KnownMethod {
        RUNTIME_GET_RUNTIME("java.lang.Runtime"),
        PATH_FACTORY("java.nio.file.Path"),
        PATH_RESOLVE("java.nio.file.Path"),
        PATH_RECEIVER_TRANSFORM("java.nio.file.Path");

        private final String returnType;

        KnownMethod(String returnType) {
            this.returnType = returnType;
        }

        public String returnType() {
            return returnType;
        }
    }
}
