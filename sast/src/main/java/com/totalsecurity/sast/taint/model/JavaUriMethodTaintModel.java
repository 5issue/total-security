package com.totalsecurity.sast.taint.model;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.rule.context.KnownMethodReturnTypes;
import java.util.Optional;

/** Propagates taint through selected exact java.net.URI construction and transforms. */
public final class JavaUriMethodTaintModel implements MethodTaintModel {
    public static final String ID = "JAVA_URI_PROPAGATION";

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
                    case URI_CREATE -> Optional.of(MethodTaintSemantics.propagateArguments());
                    case URI_NORMALIZE -> Optional.of(MethodTaintSemantics.propagateReceiver());
                    case RUNTIME_GET_RUNTIME,
                            PATH_FACTORY,
                            PATH_RESOLVE,
                            PATH_RECEIVER_TRANSFORM,
                            SERVLET_RESPONSE_GET_WRITER,
                            SERVLET_REQUEST_STRING_VALUE,
                            SERVLET_REQUEST_INPUT_STREAM,
                            SPRING_HTML_ESCAPE ->
                            Optional.empty();
                });
    }
}
