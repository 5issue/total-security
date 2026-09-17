package com.totalsecurity.sast.taint.model;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.rule.context.KnownMethodReturnTypes;
import java.util.Optional;

/** Propagates taint through selected exact Java NIO Path construction and transform APIs. */
public final class JavaNioPathMethodTaintModel implements MethodTaintModel {
    public static final String ID = "JAVA_NIO_PATH_PROPAGATION";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public Optional<MethodTaintSemantics> match(CallSiteContext context) {
        if (context.receiverQualifiedType().isEmpty()) {
            return Optional.empty();
        }
        return KnownMethodReturnTypes.match(
                        context.receiverQualifiedType().orElseThrow(),
                        context.methodName(),
                        context.argumentQualifiedTypes())
                .flatMap(known -> switch (known) {
                    case PATH_FACTORY -> Optional.of(MethodTaintSemantics.propagateArguments());
                    case PATH_RESOLVE ->
                            Optional.of(MethodTaintSemantics.propagateReceiverAndArguments());
                    case PATH_RECEIVER_TRANSFORM ->
                            Optional.of(MethodTaintSemantics.propagateReceiver());
                    case RUNTIME_GET_RUNTIME,
                            URI_CREATE,
                            URI_NORMALIZE,
                            SERVLET_RESPONSE_GET_WRITER,
                            SERVLET_REQUEST_STRING_VALUE,
                            SERVLET_REQUEST_INPUT_STREAM,
                            SPRING_HTML_ESCAPE -> Optional.empty();
                });
    }
}
