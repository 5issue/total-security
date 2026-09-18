package com.totalsecurity.sast.interprocedural;

import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.MethodKind;
import com.totalsecurity.sast.ir.TypeKind;
import com.totalsecurity.sast.ir.expression.Expression;
import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import com.totalsecurity.sast.ir.expression.VariableReference;
import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.rule.context.CallSiteContextResolver;
import com.totalsecurity.sast.rule.context.LightweightTypeContext;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Resolves exact direct same-class or project-local cross-class calls. */
public final class CrossClassCallResolver {
    private final ProjectClassIndex index;
    private final ConservativeTypeCompatibility compatibility;
    private final UniqueInterfaceImplementationResolver interfaceImplementations;

    public CrossClassCallResolver(ProjectClassIndex index) {
        this.index = Objects.requireNonNull(index, "index");
        this.compatibility = new ConservativeTypeCompatibility(index);
        this.interfaceImplementations = new UniqueInterfaceImplementationResolver(index);
    }

    public ProjectCallResolution resolve(
            ProjectMethodId caller,
            ProjectClassEntry callerType,
            MethodCallExpression call,
            CallSiteContextResolver contexts) {
        CallSiteContext context = contexts.resolve(call);
        if (context.recordAccessor().isPresent()) {
            return modeled(caller, call);
        }
        if (context.enumConstantReceiver()
                .filter(reference -> reference.constant().constantSpecificClassBody())
                .isPresent()) {
            return unsupported(caller, call, UnsupportedInterproceduralReason.DYNAMIC_RECEIVER,
                    "Enum constant-specific class body requires runtime override dispatch");
        }
        if (isSameClassSyntax(context, callerType)) {
            Optional<SameClassCallResolution> same = new SameClassCallResolver(
                    callerType.file(), callerType.type(), index)
                    .resolve(caller.method(), call, contexts);
            if (same.isEmpty()) {
                return unsupported(caller, call, UnsupportedInterproceduralReason.UNKNOWN_TARGET_METHOD,
                        "No method named " + context.methodName() + " is declared by "
                                + callerType.qualifiedName());
            }
            SameClassCallResolution resolution = same.orElseThrow();
            if (resolution.target().isPresent()) {
                return resolvedIfAnalyzable(
                        caller,
                        call,
                        callerType.qualifiedName(),
                        resolution.target().orElseThrow());
            }
            return unsupported(caller, call,
                    resolution.unsupported().orElseThrow().reason(),
                    resolution.unsupported().orElseThrow().detail());
        }

        if (context.receiver().filter(receiver -> receiver instanceof VariableReference reference
                && reference.name().equals("super")).isPresent()) {
            return unsupported(caller, call, UnsupportedInterproceduralReason.INHERITED_METHOD,
                    "super calls are outside exact project-local dispatch");
        }

        Optional<String> qualifiedReceiver = context.receiverQualifiedType();
        if (qualifiedReceiver.isEmpty()) {
            List<ProjectClassEntry> simpleCandidates = context.receiverDeclaredType()
                    .map(CrossClassCallResolver::simpleName)
                    .map(index::classesNamed)
                    .orElse(List.of());
            UnsupportedInterproceduralReason reason = simpleCandidates.size() > 1
                    ? UnsupportedInterproceduralReason.AMBIGUOUS_CLASS
                    : UnsupportedInterproceduralReason.UNKNOWN_RECEIVER_TYPE;
            return unsupported(caller, call, reason,
                    "Receiver type cannot be resolved to one exact project class");
        }

        String receiverType = qualifiedReceiver.orElseThrow();
        if (receiverType.equals(callerType.qualifiedName())) {
            return unsupported(caller, call, UnsupportedInterproceduralReason.DYNAMIC_RECEIVER,
                    "Same-class value receivers require dynamic-dispatch reasoning");
        }
        List<ProjectClassEntry> owners = index.candidates(receiverType);
        if (owners.size() > 1) {
            return unsupported(caller, call, UnsupportedInterproceduralReason.AMBIGUOUS_CLASS,
                    "Duplicate project class FQN " + receiverType);
        }
        if (owners.isEmpty()) {
            if (hasAmbiguousWildcardQualification(context)) {
                List<ProjectClassEntry> simpleCandidates = context.receiverDeclaredType()
                        .map(CrossClassCallResolver::simpleName)
                        .map(index::classesNamed)
                        .orElse(List.of());
                if (simpleCandidates.size() > 1) {
                    return unsupported(
                            caller,
                            call,
                            UnsupportedInterproceduralReason.AMBIGUOUS_CLASS,
                            "Unqualified receiver type maps to multiple wildcard-imported "
                                    + "project classes");
                }
            }
            return unsupported(caller, call, UnsupportedInterproceduralReason.EXTERNAL_CLASS,
                    "Exact receiver type " + receiverType + " is outside the project index");
        }

        ProjectClassEntry owner = owners.getFirst();
        Optional<InterfaceDispatchInfo> interfaceDispatch = Optional.empty();
        if (owner.type().kind() == TypeKind.INTERFACE) {
            if (!context.receiverBoundToValue()) {
                return unsupported(
                        caller,
                        call,
                        UnsupportedInterproceduralReason.INTERFACE_DISPATCH,
                        "Interface implementation dispatch requires a proven instance-value receiver");
            }
            ProjectClassEntry declaredInterface = owner;
            UniqueInterfaceImplementationResolver.Selection selection =
                    interfaceImplementations.select(declaredInterface);
            if (selection.implementation().isEmpty()) {
                return unsupported(
                        caller,
                        call,
                        UnsupportedInterproceduralReason.INTERFACE_DISPATCH,
                        selection.detail());
            }
            owner = selection.implementation().orElseThrow();
            interfaceDispatch = Optional.of(new InterfaceDispatchInfo(
                    declaredInterface.qualifiedName(), owner.qualifiedName()));
        }
        Optional<MethodInfo> target = resolveOverload(
                owner, context, caller, call);
        if (target.isPresent()) {
            return resolvedIfAnalyzable(
                    caller,
                    call,
                    owner.qualifiedName(),
                    target.orElseThrow(),
                    interfaceDispatch);
        }
        return overloadFailure(owner, context, caller, call);
    }

    private static boolean isSameClassSyntax(
            CallSiteContext context, ProjectClassEntry callerType) {
        if (context.receiver().isEmpty()) {
            return true;
        }
        Expression receiver = context.receiver().orElseThrow();
        if (!(receiver instanceof VariableReference reference)) {
            return false;
        }
        if (reference.name().equals("this") || reference.name().equals("super")) {
            return reference.name().equals("this");
        }
        boolean currentName = reference.name().equals(callerType.type().name())
                || reference.name().equals(callerType.qualifiedName());
        return currentName
                && !context.receiverBoundToValue()
                && context.receiverQualifiedType().filter(callerType.qualifiedName()::equals).isPresent();
    }

    private Optional<MethodInfo> resolveOverload(
            ProjectClassEntry owner,
            CallSiteContext context,
            ProjectMethodId caller,
            MethodCallExpression call) {
        List<MethodInfo> named = named(owner, context);
        if (named.isEmpty()) {
            return Optional.empty();
        }
        List<MethodInfo> sameArity = named.stream()
                .filter(method -> method.parameters().size() == context.argumentCount())
                .toList();
        if (sameArity.size() == 1
                && !hasKnownTypeMismatch(context, sameArity.getFirst(), owner)) {
            return Optional.of(sameArity.getFirst());
        }
        if (sameArity.size() > 1) {
            List<MethodInfo> exact = sameArity.stream()
                    .filter(method -> exactTypes(context, method, owner))
                    .toList();
            if (exact.size() == 1) {
                return Optional.of(exact.getFirst());
            }
            List<MethodInfo> compatible = sameArity.stream()
                    .filter(method -> match(context, method, owner)
                            == ConservativeTypeCompatibility.Match.COMPATIBLE)
                    .toList();
            boolean unknown = sameArity.stream()
                    .anyMatch(method -> match(context, method, owner)
                            == ConservativeTypeCompatibility.Match.UNKNOWN);
            if (compatible.size() == 1 && !unknown) {
                return Optional.of(compatible.getFirst());
            }
        }
        return Optional.empty();
    }

    private ProjectCallResolution overloadFailure(
            ProjectClassEntry owner,
            CallSiteContext context,
            ProjectMethodId caller,
            MethodCallExpression call) {
        List<MethodInfo> named = named(owner, context);
        if (named.isEmpty()) {
            return unsupported(caller, call, UnsupportedInterproceduralReason.UNKNOWN_TARGET_METHOD,
                    "No project method named " + context.methodName() + " on " + owner.qualifiedName());
        }
        List<MethodInfo> sameArity = named.stream()
                .filter(method -> method.parameters().size() == context.argumentCount())
                .toList();
        if (sameArity.isEmpty()) {
            return unsupported(caller, call, UnsupportedInterproceduralReason.WRONG_ARITY,
                    "No overload has argument count " + context.argumentCount());
        }
        if (sameArity.size() == 1
                && hasKnownTypeMismatch(context, sameArity.getFirst(), owner)) {
            return unsupported(caller, call,
                    UnsupportedInterproceduralReason.INCOMPATIBLE_ARGUMENT_TYPE,
                    "Known argument type is incompatible with the project method");
        }
        List<MethodInfo> compatible = sameArity.stream()
                .filter(method -> match(context, method, owner)
                        == ConservativeTypeCompatibility.Match.COMPATIBLE)
                .toList();
        boolean unknown = sameArity.stream()
                .anyMatch(method -> match(context, method, owner)
                        == ConservativeTypeCompatibility.Match.UNKNOWN);
        return unsupported(caller, call,
                compatible.size() >= 2
                        ? UnsupportedInterproceduralReason.AMBIGUOUS_OVERLOAD
                        : unknown
                                ? UnsupportedInterproceduralReason.UNKNOWN_ARGUMENT_TYPE
                                : UnsupportedInterproceduralReason.INCOMPATIBLE_ARGUMENT_TYPE,
                "Project overload cannot be resolved uniquely by conservative lightweight types");
    }

    private static List<MethodInfo> named(ProjectClassEntry owner, CallSiteContext context) {
        return owner.type().methods().stream()
                .filter(method -> method.kind() == MethodKind.METHOD)
                .filter(method -> method.name().equals(context.methodName()))
                .toList();
    }

    private boolean exactTypes(
            CallSiteContext context, MethodInfo method, ProjectClassEntry owner) {
        LightweightTypeContext types = new LightweightTypeContext(owner.file(), index::contains);
        for (int index = 0; index < context.argumentCount(); index++) {
            Optional<String> argument = context.argumentQualifiedTypes().get(index);
            if (argument.isEmpty()
                    || !compatibility.isExact(
                            argument.orElseThrow(), method, index, types)) {
                return false;
            }
        }
        return true;
    }

    private boolean hasKnownTypeMismatch(
            CallSiteContext context, MethodInfo method, ProjectClassEntry owner) {
        LightweightTypeContext types = new LightweightTypeContext(owner.file(), index::contains);
        for (int index = 0; index < context.argumentCount(); index++) {
            Optional<String> argument = context.argumentQualifiedTypes().get(index);
            if (argument.isPresent()
                    && compatibility.match(argument.orElseThrow(), method, index, types)
                            == ConservativeTypeCompatibility.Match.INCOMPATIBLE) {
                return true;
            }
        }
        return false;
    }

    private ConservativeTypeCompatibility.Match match(
            CallSiteContext context, MethodInfo method, ProjectClassEntry owner) {
        LightweightTypeContext types = new LightweightTypeContext(owner.file(), index::contains);
        boolean unknown = false;
        for (int index = 0; index < context.argumentCount(); index++) {
            Optional<String> argument = context.argumentQualifiedTypes().get(index);
            if (argument.isEmpty()) {
                unknown = true;
                continue;
            }
            ConservativeTypeCompatibility.Match current = compatibility.match(
                    argument.orElseThrow(), method, index, types);
            if (current == ConservativeTypeCompatibility.Match.INCOMPATIBLE) {
                return current;
            }
            if (current == ConservativeTypeCompatibility.Match.UNKNOWN) {
                unknown = true;
            }
        }
        return unknown
                ? ConservativeTypeCompatibility.Match.UNKNOWN
                : ConservativeTypeCompatibility.Match.COMPATIBLE;
    }

    private static String simpleName(String declaredType) {
        String value = declaredType.trim();
        int generic = value.indexOf('<');
        if (generic >= 0) {
            value = value.substring(0, generic);
        }
        while (value.endsWith("[]")) {
            value = value.substring(0, value.length() - 2).trim();
        }
        int separator = value.lastIndexOf('.');
        return separator >= 0 ? value.substring(separator + 1) : value;
    }

    private static boolean hasAmbiguousWildcardQualification(CallSiteContext context) {
        Optional<String> declared = context.receiverDeclaredType();
        if (declared.isEmpty() || declared.orElseThrow().contains(".")) {
            return false;
        }
        String simpleName = simpleName(declared.orElseThrow());
        boolean explicitlyImported = context.file().imports().stream()
                .filter(imported -> !imported.startsWith("static "))
                .anyMatch(imported -> imported.endsWith("." + simpleName));
        if (explicitlyImported) {
            return false;
        }
        return context.file().imports().stream()
                .filter(imported -> !imported.startsWith("static "))
                .filter(imported -> imported.endsWith(".*"))
                .limit(2)
                .count() > 1;
    }

    private static ProjectCallResolution resolved(
            ProjectMethodId caller,
            MethodCallExpression call,
            ProjectMethodId target,
            Optional<InterfaceDispatchInfo> interfaceDispatch) {
        return new ProjectCallResolution(
                caller, call, SameClassCallStatus.RESOLVED,
                Optional.of(target), Optional.empty(), interfaceDispatch);
    }

    private static ProjectCallResolution modeled(
            ProjectMethodId caller, MethodCallExpression call) {
        return new ProjectCallResolution(
                caller, call, SameClassCallStatus.MODELED,
                Optional.empty(), Optional.empty());
    }

    private static ProjectCallResolution resolvedIfAnalyzable(
            ProjectMethodId caller,
            MethodCallExpression call,
            String ownerQualifiedName,
            MethodInfo target) {
        return resolvedIfAnalyzable(
                caller, call, ownerQualifiedName, target, Optional.empty());
    }

    private static ProjectCallResolution resolvedIfAnalyzable(
            ProjectMethodId caller,
            MethodCallExpression call,
            String ownerQualifiedName,
            MethodInfo target,
            Optional<InterfaceDispatchInfo> interfaceDispatch) {
        if (target.body().isEmpty()) {
            return unsupported(
                    caller,
                    call,
                    UnsupportedInterproceduralReason.NO_ANALYZABLE_BODY,
                    "Project-local target " + ownerQualifiedName + "#" + target.name()
                            + " has no analyzable method body");
        }
        return resolved(
                caller,
                call,
                new ProjectMethodId(ownerQualifiedName, target),
                interfaceDispatch);
    }

    private static ProjectCallResolution unsupported(
            ProjectMethodId caller,
            MethodCallExpression call,
            UnsupportedInterproceduralReason reason,
            String detail) {
        return new ProjectCallResolution(
                caller, call, SameClassCallStatus.UNSUPPORTED, Optional.empty(),
                Optional.of(new UnsupportedInterproceduralFlow(reason, detail, call.location())));
    }
}
