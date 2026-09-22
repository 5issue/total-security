package com.totalsecurity.sast.rule.sink;

import com.totalsecurity.sast.interprocedural.ProjectClassIndex;
import com.totalsecurity.sast.ir.MethodKind;
import com.totalsecurity.sast.ir.expression.Expression;
import com.totalsecurity.sast.ir.expression.FieldAccessExpression;
import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import com.totalsecurity.sast.ir.expression.VariableReference;
import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.rule.context.LightweightTypeContext;
import com.totalsecurity.sast.rule.context.ProjectTypeDeclaration;
import com.totalsecurity.sast.rule.context.ProjectTypeLookup;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;

/** Exact RabbitTemplate convertAndSend overloads used by the audited backend. */
public final class SpringRabbitTemplateMessageSinkRule implements SinkRule {
    public static final String ID = "SPRING_RABBIT_TEMPLATE_MESSAGE_PAYLOAD";
    private static final String RECEIVER = "org.springframework.amqp.rabbit.core.RabbitTemplate";
    private static final String STRING = "java.lang.String";
    private static final String MESSAGE_POST_PROCESSOR =
            "org.springframework.amqp.core.MessagePostProcessor";
    private static final String CORRELATION_DATA =
            "org.springframework.amqp.rabbit.connection.CorrelationData";
    private final ProjectTypeLookup projectTypes;

    public SpringRabbitTemplateMessageSinkRule() {
        this(ProjectTypeLookup.none());
    }

    public SpringRabbitTemplateMessageSinkRule(ProjectTypeLookup projectTypes) {
        this.projectTypes = java.util.Objects.requireNonNull(projectTypes, "projectTypes");
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public Optional<SinkMatch> match(CallSiteContext context) {
        Classification classification = classify(context);
        if (classification.status() != ClassificationStatus.MATCHED) {
            return Optional.empty();
        }
        int payloadIndex = classification.payloadIndex().orElseThrow();
        return Optional.of(new SinkMatch(
                ID,
                SinkCategory.ASYNC_MESSAGE_PUBLISH,
                context.call(),
                Set.of(payloadIndex),
                context.location(),
                "exact Spring RabbitTemplate.convertAndSend message payload argument "
                        + payloadIndex));
    }

    public Classification classify(CallSiteContext context) {
        if (!context.receiverBoundToValue()
                || context.receiverQualifiedType().filter(RECEIVER::equals).isEmpty()
                || !context.methodName().equals("convertAndSend")) {
            return Classification.notApplicable();
        }
        return switch (context.argumentCount()) {
            case 3 -> classifyThreeArguments(context);
            case 4 -> classifyFourArguments(context);
            case 5 -> classifyFiveArguments(context);
            default -> Classification.unsupported(
                    "Unsupported RabbitTemplate.convertAndSend arity");
        };
    }

    private Classification classifyThreeArguments(CallSiteContext context) {
        if (hasType(context, 0, STRING)
                && (hasType(context, 2, MESSAGE_POST_PROCESSOR)
                        || hasType(context, 2, CORRELATION_DATA))
                && !hasType(context, 1, MESSAGE_POST_PROCESSOR)) {
            return Classification.matched(1);
        }
        if (hasType(context, 0, STRING)
                && hasType(context, 1, STRING)
                && knownNonCallbackType(context, 2)) {
            return Classification.matched(2);
        }
        return Classification.unsupported(
                "RabbitTemplate.convertAndSend 3-argument overload is ambiguous or unsupported");
    }

    private Classification classifyFourArguments(CallSiteContext context) {
        if (hasType(context, 0, STRING)
                && hasType(context, 2, MESSAGE_POST_PROCESSOR)
                && hasType(context, 3, CORRELATION_DATA)) {
            return Classification.matched(1);
        }
        if (hasType(context, 0, STRING)
                && hasType(context, 1, STRING)
                && knownNonCallbackType(context, 2)
                && callbackOrUnknown(context, 3)) {
            return Classification.matched(2);
        }
        return Classification.unsupported(
                "RabbitTemplate.convertAndSend 4-argument overload is ambiguous or unsupported");
    }

    private Classification classifyFiveArguments(CallSiteContext context) {
        if (hasType(context, 0, STRING)
                && hasType(context, 1, STRING)
                && knownNonCallbackType(context, 2)
                && callbackOrUnknown(context, 3)
                && hasType(context, 4, CORRELATION_DATA)) {
            return Classification.matched(2);
        }
        return Classification.unsupported(
                "RabbitTemplate.convertAndSend 5-argument overload is ambiguous or unsupported");
    }

    private static boolean hasType(CallSiteContext context, int index, String type) {
        return context.argumentHasType(index, type);
    }

    private boolean knownNonCallbackType(CallSiteContext context, int index) {
        Optional<String> known = context.argumentQualifiedTypes().get(index);
        if (known.isPresent()) {
            return !known.orElseThrow().equals(MESSAGE_POST_PROCESSOR)
                    && !known.orElseThrow().equals(CORRELATION_DATA);
        }
        return exactProjectStringReturn(context.arguments().get(index), context);
    }

    private static boolean callbackOrUnknown(CallSiteContext context, int index) {
        return context.argumentQualifiedTypes().get(index).isEmpty()
                || hasType(context, index, MESSAGE_POST_PROCESSOR)
                || hasType(context, index, CORRELATION_DATA);
    }

    private boolean exactProjectStringReturn(
            Expression expression, CallSiteContext context) {
        if (!(expression instanceof MethodCallExpression call)) {
            return false;
        }
        Optional<String> ownerName = exactProjectCallOwner(call, context);
        if (ownerName.isEmpty() || projectTypes.isAmbiguous(ownerName.orElseThrow())) {
            return false;
        }
        List<ProjectTypeDeclaration> declarations =
                projectTypes.declarations(ownerName.orElseThrow());
        if (declarations.size() != 1) {
            return false;
        }
        ProjectTypeDeclaration owner = declarations.getFirst();
        var methods = owner.type().methods().stream()
                .filter(method -> method.kind() == MethodKind.METHOD)
                .filter(method -> method.name().equals(call.call().methodName()))
                .filter(method -> method.parameters().size() == call.call().arguments().size())
                .toList();
        if (methods.size() != 1) {
            return false;
        }
        LightweightTypeContext ownerTypes =
                new LightweightTypeContext(owner.file(), projectTypes, owner.type());
        return methods.getFirst().returnType()
                .flatMap(ownerTypes::qualifyTypeShape)
                .filter(STRING::equals)
                .isPresent();
    }

    private static Optional<String> exactProjectCallOwner(
            MethodCallExpression call, CallSiteContext context) {
        if (call.call().receiver().isEmpty()) {
            return Optional.of(ProjectClassIndex.qualifiedName(
                    context.file(), context.enclosingClass()));
        }
        Expression receiver = call.call().receiver().orElseThrow();
        if (receiver instanceof VariableReference reference) {
            if (reference.name().equals("this")) {
                return Optional.of(ProjectClassIndex.qualifiedName(
                        context.file(), context.enclosingClass()));
            }
            return context.enclosingClass().fields().stream()
                    .filter(field -> field.name().equals(reference.name()))
                    .map(field -> field.type())
                    .findFirst()
                    .flatMap(context.types()::qualifyType);
        }
        if (receiver instanceof FieldAccessExpression field
                && field.target() instanceof VariableReference target
                && target.name().equals("this")) {
            return context.enclosingClass().fields().stream()
                    .filter(candidate -> candidate.name().equals(field.fieldName()))
                    .map(candidate -> candidate.type())
                    .findFirst()
                    .flatMap(context.types()::qualifyType);
        }
        return Optional.empty();
    }

    public enum ClassificationStatus {
        NOT_APPLICABLE,
        MATCHED,
        UNSUPPORTED
    }

    public record Classification(
            ClassificationStatus status, OptionalInt payloadIndex, String reason) {
        public Classification {
            java.util.Objects.requireNonNull(status, "status");
            java.util.Objects.requireNonNull(payloadIndex, "payloadIndex");
            java.util.Objects.requireNonNull(reason, "reason");
            if (status == ClassificationStatus.MATCHED != payloadIndex.isPresent()) {
                throw new IllegalArgumentException(
                        "Only a matched RabbitTemplate overload has a payload index");
            }
        }

        static Classification notApplicable() {
            return new Classification(
                    ClassificationStatus.NOT_APPLICABLE, OptionalInt.empty(), "");
        }

        static Classification matched(int payloadIndex) {
            return new Classification(
                    ClassificationStatus.MATCHED, OptionalInt.of(payloadIndex), "");
        }

        static Classification unsupported(String reason) {
            return new Classification(
                    ClassificationStatus.UNSUPPORTED, OptionalInt.empty(), reason);
        }
    }
}
