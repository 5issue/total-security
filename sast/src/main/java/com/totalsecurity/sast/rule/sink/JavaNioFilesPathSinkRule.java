package com.totalsecurity.sast.rule.sink;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Matches selected java.nio.file.Files APIs whose first argument is a Path. */
public final class JavaNioFilesPathSinkRule implements SinkRule {
    public static final String ID = "JAVA_NIO_FILESYSTEM_PATH";
    private static final String RECEIVER = "java.nio.file.Files";
    private static final Map<String, Arity> METHODS = Map.of(
            "readString", new Arity(1, 2),
            "readAllBytes", new Arity(1, 1),
            "newInputStream", new Arity(1, Integer.MAX_VALUE),
            "newBufferedReader", new Arity(1, 2),
            "writeString", new Arity(2, Integer.MAX_VALUE),
            "newOutputStream", new Arity(1, Integer.MAX_VALUE),
            "delete", new Arity(1, 1),
            "deleteIfExists", new Arity(1, 1));

    @Override
    public String id() {
        return ID;
    }

    @Override
    public Optional<SinkMatch> match(CallSiteContext context) {
        Arity arity = METHODS.get(context.methodName());
        if (!context.receiverQualifiedType().filter(RECEIVER::equals).isPresent()
                || arity == null
                || !arity.accepts(context.argumentCount())
                || !context.argumentHasType(0, "java.nio.file.Path")) {
            return Optional.empty();
        }
        return Optional.of(new SinkMatch(
                ID,
                SinkCategory.FILESYSTEM_PATH,
                context.call(),
                Set.of(0),
                context.location(),
                RECEIVER + "." + context.methodName() + " filesystem Path argument 0"));
    }

    private record Arity(int minimum, int maximum) {
        private boolean accepts(int value) {
            return value >= minimum && value <= maximum;
        }
    }
}
