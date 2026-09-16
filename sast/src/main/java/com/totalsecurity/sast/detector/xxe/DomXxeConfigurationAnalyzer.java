package com.totalsecurity.sast.detector.xxe;

import com.totalsecurity.sast.cfg.BasicBlock;
import com.totalsecurity.sast.cfg.ControlFlowGraph;
import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.VariableSymbol;
import com.totalsecurity.sast.finding.ConfigurationEvidence;
import com.totalsecurity.sast.ir.AssignmentInfo;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.VariableInfo;
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
import com.totalsecurity.sast.ir.statement.DoWhileStatement;
import com.totalsecurity.sast.ir.statement.EnhancedForStatement;
import com.totalsecurity.sast.ir.statement.ExpressionStatement;
import com.totalsecurity.sast.ir.statement.ForStatement;
import com.totalsecurity.sast.ir.statement.IfStatement;
import com.totalsecurity.sast.ir.statement.ReturnStatement;
import com.totalsecurity.sast.ir.statement.Statement;
import com.totalsecurity.sast.ir.statement.SwitchStatement;
import com.totalsecurity.sast.ir.statement.ThrowStatement;
import com.totalsecurity.sast.ir.statement.VariableDeclarationStatement;
import com.totalsecurity.sast.ir.statement.WhileStatement;
import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.rule.context.CallSiteContextResolver;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Flow-sensitive state analysis for direct local DocumentBuilderFactory/DocumentBuilder identities.
 * Factory state is snapshotted when a builder is created. Ambiguous path merges are not confirmed.
 */
public final class DomXxeConfigurationAnalyzer {
    static final String FACTORY_TYPE = "javax.xml.parsers.DocumentBuilderFactory";
    static final String PARSER_TYPE = "javax.xml.parsers.DocumentBuilder";
    static final String XML_CONSTANTS_TYPE = "javax.xml.XMLConstants";
    static final String ACCESS_EXTERNAL_DTD =
            "http://javax.xml.XMLConstants/property/accessExternalDTD";

    public List<UnsafeDomParserUse> analyze(
            JavaFileInfo file,
            ClassInfo enclosingClass,
            MethodInfo method,
            DataFlowResult dataFlow) {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(enclosingClass, "enclosingClass");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(dataFlow, "dataFlow");
        if (!dataFlow.graph().method().equals(method)) {
            throw new IllegalArgumentException("DataFlowResult belongs to a different method");
        }

        AnalysisContext context = new AnalysisContext(
                dataFlow, new CallSiteContextResolver(file, enclosingClass, method, dataFlow));
        Map<BasicBlock, AnalysisState> inStates = solve(dataFlow.graph(), context);
        LinkedHashMap<SourceLocation, UnsafeDomParserUse> uses = new LinkedHashMap<>();
        for (BasicBlock block : dataFlow.graph().blocks()) {
            AnalysisState incoming = inStates.get(block);
            if (incoming == null || !dataFlow.graph().reachableBlocks().contains(block)) {
                continue;
            }
            transfer(block, incoming, context, use -> uses.merge(
                    use.parseLocation(), use, DomXxeConfigurationAnalyzer::mergeSameParse));
        }
        return uses.values().stream()
                .sorted(Comparator.comparingInt(use -> use.parseLocation().startLine()))
                .toList();
    }

    private static Map<BasicBlock, AnalysisState> solve(
            ControlFlowGraph graph, AnalysisContext context) {
        Map<BasicBlock, AnalysisState> inStates = new LinkedHashMap<>();
        Map<BasicBlock, AnalysisState> outStates = new LinkedHashMap<>();
        ArrayDeque<BasicBlock> work = new ArrayDeque<>();
        Set<BasicBlock> queued = new LinkedHashSet<>();
        work.add(graph.entry());
        queued.add(graph.entry());

        while (!work.isEmpty()) {
            BasicBlock block = work.removeFirst();
            queued.remove(block);
            AnalysisState incoming;
            if (block.equals(graph.entry())) {
                incoming = AnalysisState.empty();
            } else {
                List<AnalysisState> predecessorStates = graph.predecessors(block).stream()
                        .map(outStates::get)
                        .filter(Objects::nonNull)
                        .toList();
                if (predecessorStates.isEmpty()) {
                    continue;
                }
                incoming = predecessorStates.getFirst();
                for (int index = 1; index < predecessorStates.size(); index++) {
                    incoming = incoming.join(predecessorStates.get(index));
                }
            }
            inStates.put(block, incoming);
            AnalysisState outgoing = transfer(block, incoming, context, ignored -> {});
            if (!outgoing.equals(outStates.put(block, outgoing))) {
                for (BasicBlock successor : graph.successors(block)) {
                    if (queued.add(successor)) {
                        work.addLast(successor);
                    }
                }
            }
        }
        return Map.copyOf(inStates);
    }

    private static AnalysisState transfer(
            BasicBlock block,
            AnalysisState incoming,
            AnalysisContext context,
            java.util.function.Consumer<UnsafeDomParserUse> findingConsumer) {
        MutableState state = new MutableState(incoming);
        for (Statement statement : block.statements()) {
            processStatement(statement, state, context, findingConsumer);
        }
        block.controlStatement().ifPresent(statement ->
                controlExpression(statement).ifPresent(expression ->
                        processExpression(expression, state, context, findingConsumer)));
        return state.freeze();
    }

    private static void processStatement(
            Statement statement,
            MutableState state,
            AnalysisContext context,
            java.util.function.Consumer<UnsafeDomParserUse> findingConsumer) {
        switch (statement) {
            case VariableDeclarationStatement declaration -> {
                for (VariableInfo variable : declaration.variables()) {
                    variable.initializer().ifPresent(expression ->
                            processExpression(expression, state, context, findingConsumer));
                    context.symbol(variable).ifPresent(symbol ->
                            bindAssignedValue(symbol, variable.initializer(), state, context));
                }
            }
            case ExpressionStatement expression ->
                    processExpression(expression.expression(), state, context, findingConsumer);
            case ReturnStatement returned -> returned.expression().ifPresent(expression ->
                    processExpression(expression, state, context, findingConsumer));
            case ThrowStatement thrown ->
                    processExpression(thrown.expression(), state, context, findingConsumer);
            default -> {
                // Nested control statements are represented in separate CFG blocks.
            }
        }
    }

    private static void processExpression(
            Expression expression,
            MutableState state,
            AnalysisContext context,
            java.util.function.Consumer<UnsafeDomParserUse> findingConsumer) {
        switch (expression) {
            case VariableReference ignored -> {
            }
            case Literal ignored -> {
            }
            case UnknownExpression ignored -> {
            }
            case BinaryExpression binary -> {
                processExpression(binary.left(), state, context, findingConsumer);
                processExpression(binary.right(), state, context, findingConsumer);
            }
            case AssignmentExpression assignment -> {
                AssignmentInfo info = assignment.assignment();
                processExpression(info.left(), state, context, findingConsumer);
                processExpression(info.right(), state, context, findingConsumer);
                if (info.left() instanceof VariableReference reference) {
                    context.symbol(reference).ifPresent(symbol ->
                            bindAssignedValue(symbol, Optional.of(info.right()), state, context));
                }
            }
            case MethodCallExpression call -> {
                call.call().receiver().ifPresent(receiver ->
                        processExpression(receiver, state, context, findingConsumer));
                call.call().arguments().forEach(argument ->
                        processExpression(argument, state, context, findingConsumer));
                applyCall(call, state, context, findingConsumer);
            }
            case ObjectCreationExpression creation -> creation.arguments().forEach(argument ->
                    processExpression(argument, state, context, findingConsumer));
            case FieldAccessExpression field ->
                    processExpression(field.target(), state, context, findingConsumer);
            case ParenthesizedExpression parenthesized ->
                    processExpression(parenthesized.expression(), state, context, findingConsumer);
        }
    }

    private static void applyCall(
            MethodCallExpression expression,
            MutableState state,
            AnalysisContext context,
            java.util.function.Consumer<UnsafeDomParserUse> findingConsumer) {
        CallSiteContext call = context.calls.resolve(expression);
        if (call.receiverQualifiedType().filter(FACTORY_TYPE::equals).isPresent()) {
            configurationWrite(call, context).ifPresent(write -> receiverSymbol(call, context).ifPresent(symbol -> {
                FactoryBinding binding = state.factories.get(symbol);
                if (binding != null && binding.kind == BindingKind.CONCRETE) {
                    FactoryInstance updated = binding.factory.with(write);
                    state.factories.put(symbol, FactoryBinding.concrete(updated));
                }
            }));
            return;
        }
        if (!isSupportedParse(call)) {
            return;
        }
        receiverSymbol(call, context).ifPresent(symbol -> {
            BuilderBinding binding = state.builders.get(symbol);
            if (binding == null || binding.kind != BindingKind.CONCRETE) {
                return;
            }
            ProvenConfiguration proven = provenConfiguration(binding.builder);
            if (!proven.paths.isEmpty()) {
                findingConsumer.accept(new UnsafeDomParserUse(
                        FACTORY_TYPE,
                        PARSER_TYPE,
                        proven.paths,
                        proven.evidence,
                        binding.builder.creationLocation,
                        call.location()));
            }
        });
    }

    private static void bindAssignedValue(
            VariableSymbol symbol,
            Optional<Expression> assigned,
            MutableState state,
            AnalysisContext context) {
        Optional<String> qualifiedType = context.calls.types().qualifyType(symbol.declaredType());
        if (qualifiedType.filter(FACTORY_TYPE::equals).isPresent()) {
            FactoryBinding binding = assigned
                    .flatMap(DomXxeConfigurationAnalyzer::directMethodCall)
                    .filter(call -> isFactoryCreation(context.calls.resolve(call)))
                    .map(call -> FactoryBinding.concrete(new FactoryInstance(
                            new ObjectIdentity(symbol.id(), call.location()),
                            Map.of(),
                            AccessValue.unset())))
                    .orElse(FactoryBinding.unknown());
            state.factories.put(symbol, binding);
            return;
        }
        if (qualifiedType.filter(PARSER_TYPE::equals).isEmpty()) {
            return;
        }
        BuilderBinding binding = assigned
                .flatMap(DomXxeConfigurationAnalyzer::directMethodCall)
                .filter(call -> isBuilderCreation(context.calls.resolve(call)))
                .flatMap(call -> receiverSymbol(context.calls.resolve(call), context)
                        .map(state.factories::get)
                        .filter(Objects::nonNull)
                        .filter(factory -> factory.kind == BindingKind.CONCRETE)
                        .map(factory -> BuilderBinding.concrete(new BuilderInstance(
                                new ObjectIdentity(symbol.id(), call.location()),
                                factory.factory.identity,
                                factory.factory.configuration,
                                factory.factory.externalAccess,
                                call.location()))))
                .orElse(BuilderBinding.unknown());
        state.builders.put(symbol, binding);
    }

    private static Optional<MethodCallExpression> directMethodCall(Expression expression) {
        Expression current = expression;
        while (current instanceof ParenthesizedExpression parenthesized) {
            current = parenthesized.expression();
        }
        return current instanceof MethodCallExpression call ? Optional.of(call) : Optional.empty();
    }

    private static Optional<VariableSymbol> receiverSymbol(
            CallSiteContext call, AnalysisContext context) {
        return call.receiver()
                .filter(VariableReference.class::isInstance)
                .map(VariableReference.class::cast)
                .flatMap(context::symbol);
    }

    private static boolean isFactoryCreation(CallSiteContext call) {
        return call.receiverQualifiedType().filter(FACTORY_TYPE::equals).isPresent()
                && call.methodName().equals("newInstance")
                && call.arguments().isEmpty();
    }

    private static boolean isBuilderCreation(CallSiteContext call) {
        return call.receiverQualifiedType().filter(FACTORY_TYPE::equals).isPresent()
                && call.methodName().equals("newDocumentBuilder")
                && call.arguments().isEmpty();
    }

    private static boolean isSupportedParse(CallSiteContext call) {
        if (call.receiverQualifiedType().filter(PARSER_TYPE::equals).isEmpty()
                || !call.methodName().equals("parse")) {
            return false;
        }
        List<Optional<String>> types = call.argumentQualifiedTypes();
        if (types.size() == 1) {
            return hasType(types, 0, "java.io.InputStream")
                    || hasType(types, 0, "java.lang.String")
                    || hasType(types, 0, "java.io.File")
                    || hasType(types, 0, "org.xml.sax.InputSource");
        }
        return types.size() == 2
                && hasType(types, 0, "java.io.InputStream")
                && hasType(types, 1, "java.lang.String");
    }

    private static boolean hasType(List<Optional<String>> types, int index, String expected) {
        return types.get(index).filter(expected::equals).isPresent();
    }

    private static Optional<FactoryWrite> configurationWrite(
            CallSiteContext call, AnalysisContext context) {
        if (call.methodName().equals("setFeature") && call.arguments().size() == 2) {
            Optional<String> feature = stringLiteral(call.arguments().get(0));
            if (feature.isEmpty()) {
                return Optional.empty();
            }
            Optional<ConfigurationKey> key = ConfigurationKey.forFeature(feature.orElseThrow());
            if (key.isEmpty()) {
                return Optional.empty();
            }
            Optional<Boolean> value = booleanLiteral(call.arguments().get(1));
            if (value.isEmpty()) {
                return Optional.of(new FeatureWrite(
                        key.orElseThrow(), SettingDisposition.UNKNOWN, Optional.empty()));
            }
            boolean configuredValue = value.orElseThrow();
            return Optional.of(new FeatureWrite(
                    key.orElseThrow(),
                    configuredValue == key.orElseThrow().unsafeValue
                            ? SettingDisposition.UNSAFE
                            : SettingDisposition.SAFE,
                    Optional.of(new ConfigurationEvidence(
                            "DocumentBuilderFactory.setFeature",
                            key.orElseThrow().externalName,
                            Boolean.toString(configuredValue),
                            call.location()))));
        }
        if (call.methodName().equals("setAttribute")
                && call.arguments().size() == 2
                && isAccessExternalDtdProperty(call.arguments().get(0), call, context)) {
            Optional<String> value = stringLiteral(call.arguments().get(1));
            if (value.isEmpty()) {
                return Optional.of(new ExternalAccessWrite(AccessValue.unknown()));
            }
            String configuredValue = value.orElseThrow();
            ExternalAccessState state = configuredValue.trim().isEmpty()
                    ? ExternalAccessState.DENY
                    : ExternalAccessState.ALLOW;
            return Optional.of(new ExternalAccessWrite(new AccessValue(
                    state,
                    Set.of(new ConfigurationEvidence(
                            "DocumentBuilderFactory.setAttribute",
                            ACCESS_EXTERNAL_DTD,
                            configuredValue,
                            call.location())))));
        }
        return Optional.empty();
    }

    private static boolean isAccessExternalDtdProperty(
            Expression expression, CallSiteContext call, AnalysisContext context) {
        Optional<String> literal = stringLiteral(expression);
        if (literal.filter(ACCESS_EXTERNAL_DTD::equals).isPresent()) {
            return true;
        }
        Expression unwrapped = unwrap(expression);
        if (!(unwrapped instanceof FieldAccessExpression field)
                || !field.fieldName().equals("ACCESS_EXTERNAL_DTD")
                || !(field.target() instanceof VariableReference typeReference)) {
            return false;
        }
        if (context.symbol(typeReference).isPresent()) {
            return false;
        }
        if (call.types().file().types().stream()
                .anyMatch(type -> type.name().equals(typeReference.name()))) {
            return false;
        }
        return call.types().qualifyType(typeReference.name())
                .filter(XML_CONSTANTS_TYPE::equals)
                .isPresent();
    }

    private static Optional<String> stringLiteral(Expression expression) {
        Expression unwrapped = unwrap(expression);
        if (!(unwrapped instanceof Literal literal) || !literal.kind().equals("string_literal")) {
            return Optional.empty();
        }
        String source = literal.source();
        if (source.length() < 2 || source.charAt(0) != '"' || source.charAt(source.length() - 1) != '"') {
            return Optional.empty();
        }
        return Optional.of(source.substring(1, source.length() - 1));
    }

    private static Optional<Boolean> booleanLiteral(Expression expression) {
        Expression unwrapped = unwrap(expression);
        if (!(unwrapped instanceof Literal literal)) {
            return Optional.empty();
        }
        return switch (literal.kind()) {
            case "true" -> Optional.of(true);
            case "false" -> Optional.of(false);
            default -> Optional.empty();
        };
    }

    private static ProvenConfiguration provenConfiguration(BuilderInstance builder) {
        EnumSet<ExternalResolutionPath> paths = EnumSet.noneOf(ExternalResolutionPath.class);
        LinkedHashSet<ConfigurationEvidence> evidence = new LinkedHashSet<>();
        if (!isUnsafe(builder, ConfigurationKey.DISALLOW_DOCTYPE_DECL)
                || builder.externalAccess.state != ExternalAccessState.ALLOW) {
            return new ProvenConfiguration(Set.of(), List.of());
        }
        addPathIfProven(
                builder,
                ConfigurationKey.EXTERNAL_GENERAL_ENTITIES,
                ExternalResolutionPath.GENERAL_ENTITY,
                paths,
                evidence);
        addPathIfProven(
                builder,
                ConfigurationKey.EXTERNAL_PARAMETER_ENTITIES,
                ExternalResolutionPath.PARAMETER_ENTITY,
                paths,
                evidence);
        addPathIfProven(
                builder,
                ConfigurationKey.LOAD_EXTERNAL_DTD,
                ExternalResolutionPath.EXTERNAL_DTD,
                paths,
                evidence);
        if (!paths.isEmpty()) {
            evidence.addAll(builder.configuration
                    .get(ConfigurationKey.DISALLOW_DOCTYPE_DECL).evidence);
            evidence.addAll(builder.externalAccess.evidence);
        }
        List<ConfigurationEvidence> orderedEvidence = evidence.stream()
                .sorted(Comparator.comparingInt((ConfigurationEvidence item) ->
                                item.location().startLine())
                        .thenComparingInt(item -> item.location().startColumn()))
                .toList();
        return new ProvenConfiguration(Set.copyOf(paths), orderedEvidence);
    }

    private static void addPathIfProven(
            BuilderInstance builder,
            ConfigurationKey key,
            ExternalResolutionPath path,
            Set<ExternalResolutionPath> paths,
            Set<ConfigurationEvidence> evidence) {
        if (!isUnsafe(builder, key)) {
            return;
        }
        paths.add(path);
        evidence.addAll(builder.configuration.get(key).evidence);
    }

    private static boolean isUnsafe(BuilderInstance builder, ConfigurationKey key) {
        SettingValue value = builder.configuration.get(key);
        return value != null && value.disposition == SettingDisposition.UNSAFE;
    }

    private static Expression unwrap(Expression expression) {
        Expression current = expression;
        while (current instanceof ParenthesizedExpression parenthesized) {
            current = parenthesized.expression();
        }
        return current;
    }

    private static Optional<Expression> controlExpression(Statement statement) {
        return switch (statement) {
            case IfStatement conditional -> Optional.of(conditional.condition());
            case WhileStatement loop -> Optional.of(loop.condition());
            case DoWhileStatement loop -> Optional.of(loop.condition());
            case ForStatement loop -> loop.condition();
            case EnhancedForStatement loop -> Optional.of(loop.iterable());
            case SwitchStatement selection -> Optional.of(selection.selector());
            default -> Optional.empty();
        };
    }

    private static UnsafeDomParserUse mergeSameParse(
            UnsafeDomParserUse left, UnsafeDomParserUse right) {
        if (!left.parserCreationLocation().equals(right.parserCreationLocation())) {
            return left;
        }
        LinkedHashSet<ExternalResolutionPath> paths = new LinkedHashSet<>(left.provenPaths());
        paths.addAll(right.provenPaths());
        LinkedHashSet<ConfigurationEvidence> evidence = new LinkedHashSet<>(left.provenConfigurations());
        evidence.addAll(right.provenConfigurations());
        return new UnsafeDomParserUse(
                left.factoryType(),
                left.parserType(),
                paths,
                evidence.stream()
                        .sorted(Comparator.comparingInt(item -> item.location().startLine()))
                        .toList(),
                left.parserCreationLocation(),
                left.parseLocation());
    }

    private enum ConfigurationKey {
        DISALLOW_DOCTYPE_DECL(
                "http://apache.org/xml/features/disallow-doctype-decl", false),
        EXTERNAL_GENERAL_ENTITIES(
                "http://xml.org/sax/features/external-general-entities", true),
        EXTERNAL_PARAMETER_ENTITIES(
                "http://xml.org/sax/features/external-parameter-entities", true),
        LOAD_EXTERNAL_DTD(
                "http://apache.org/xml/features/nonvalidating/load-external-dtd", true);

        private final String externalName;
        private final boolean unsafeValue;

        ConfigurationKey(String externalName, boolean unsafeValue) {
            this.externalName = externalName;
            this.unsafeValue = unsafeValue;
        }

        private static Optional<ConfigurationKey> forFeature(String feature) {
            return java.util.Arrays.stream(values())
                    .filter(key -> key.externalName.equals(feature))
                    .findFirst();
        }
    }

    private enum SettingDisposition {
        SAFE,
        UNSAFE,
        UNKNOWN
    }

    private enum ExternalAccessState {
        ALLOW,
        DENY,
        UNKNOWN,
        UNSET
    }

    private enum BindingKind {
        CONCRETE,
        UNKNOWN
    }

    private sealed interface FactoryWrite permits FeatureWrite, ExternalAccessWrite {}

    private record FeatureWrite(
            ConfigurationKey key,
            SettingDisposition disposition,
            Optional<ConfigurationEvidence> evidence) implements FactoryWrite {
        private FeatureWrite {
            evidence = Objects.requireNonNull(evidence, "evidence");
        }
    }

    private record ExternalAccessWrite(AccessValue value) implements FactoryWrite {
        private ExternalAccessWrite {
            Objects.requireNonNull(value, "value");
        }
    }

    private record SettingValue(
            SettingDisposition disposition, Set<ConfigurationEvidence> evidence) {
        private SettingValue {
            evidence = Set.copyOf(evidence);
        }

        private static SettingValue of(FeatureWrite write) {
            return new SettingValue(
                    write.disposition,
                    write.evidence.map(Set::of).orElseGet(Set::of));
        }

        private SettingValue join(SettingValue other) {
            if (other == null || disposition != other.disposition) {
                return new SettingValue(SettingDisposition.UNKNOWN, Set.of());
            }
            if (disposition == SettingDisposition.UNKNOWN) {
                return this;
            }
            LinkedHashSet<ConfigurationEvidence> merged = new LinkedHashSet<>(evidence);
            merged.addAll(other.evidence);
            return new SettingValue(disposition, merged);
        }
    }

    private record AccessValue(
            ExternalAccessState state, Set<ConfigurationEvidence> evidence) {
        private AccessValue {
            Objects.requireNonNull(state, "state");
            evidence = Set.copyOf(evidence);
        }

        private static AccessValue unset() {
            return new AccessValue(ExternalAccessState.UNSET, Set.of());
        }

        private static AccessValue unknown() {
            return new AccessValue(ExternalAccessState.UNKNOWN, Set.of());
        }

        private AccessValue join(AccessValue other) {
            if (state != other.state) {
                return unknown();
            }
            if (state == ExternalAccessState.UNKNOWN || state == ExternalAccessState.UNSET) {
                return this;
            }
            LinkedHashSet<ConfigurationEvidence> merged = new LinkedHashSet<>(evidence);
            merged.addAll(other.evidence);
            return new AccessValue(state, merged);
        }
    }

    private record ProvenConfiguration(
            Set<ExternalResolutionPath> paths, List<ConfigurationEvidence> evidence) {
        private ProvenConfiguration {
            paths = Set.copyOf(paths);
            evidence = List.copyOf(evidence);
        }
    }

    private record ObjectIdentity(int symbolId, SourceLocation creationLocation) {}

    private record FactoryInstance(
            ObjectIdentity identity,
            Map<ConfigurationKey, SettingValue> configuration,
            AccessValue externalAccess) {
        private FactoryInstance {
            configuration = Map.copyOf(configuration);
            Objects.requireNonNull(externalAccess, "externalAccess");
        }

        private FactoryInstance with(FactoryWrite write) {
            return switch (write) {
                case FeatureWrite feature -> {
                    EnumMap<ConfigurationKey, SettingValue> updated =
                            new EnumMap<>(ConfigurationKey.class);
                    updated.putAll(configuration);
                    updated.put(feature.key, SettingValue.of(feature));
                    yield new FactoryInstance(identity, updated, externalAccess);
                }
                case ExternalAccessWrite access ->
                        new FactoryInstance(identity, configuration, access.value);
            };
        }

        private FactoryInstance join(FactoryInstance other) {
            EnumMap<ConfigurationKey, SettingValue> merged = new EnumMap<>(ConfigurationKey.class);
            for (ConfigurationKey key : ConfigurationKey.values()) {
                SettingValue left = configuration.get(key);
                SettingValue right = other.configuration.get(key);
                if (left != null) {
                    merged.put(key, left.join(right));
                } else if (right != null) {
                    merged.put(key, new SettingValue(SettingDisposition.UNKNOWN, Set.of()));
                }
            }
            return new FactoryInstance(identity, merged, externalAccess.join(other.externalAccess));
        }
    }

    private record BuilderInstance(
            ObjectIdentity identity,
            ObjectIdentity factoryIdentity,
            Map<ConfigurationKey, SettingValue> configuration,
            AccessValue externalAccess,
            SourceLocation creationLocation) {
        private BuilderInstance {
            configuration = Map.copyOf(configuration);
            Objects.requireNonNull(externalAccess, "externalAccess");
        }

        private BuilderInstance join(BuilderInstance other) {
            EnumMap<ConfigurationKey, SettingValue> merged = new EnumMap<>(ConfigurationKey.class);
            for (ConfigurationKey key : ConfigurationKey.values()) {
                SettingValue left = configuration.get(key);
                SettingValue right = other.configuration.get(key);
                if (left != null) {
                    merged.put(key, left.join(right));
                } else if (right != null) {
                    merged.put(key, new SettingValue(SettingDisposition.UNKNOWN, Set.of()));
                }
            }
            return new BuilderInstance(
                    identity,
                    factoryIdentity,
                    merged,
                    externalAccess.join(other.externalAccess),
                    creationLocation);
        }
    }

    private static final class FactoryBinding {
        private final BindingKind kind;
        private final FactoryInstance factory;

        private FactoryBinding(BindingKind kind, FactoryInstance factory) {
            this.kind = kind;
            this.factory = factory;
        }

        private static FactoryBinding concrete(FactoryInstance factory) {
            return new FactoryBinding(BindingKind.CONCRETE, factory);
        }

        private static FactoryBinding unknown() {
            return new FactoryBinding(BindingKind.UNKNOWN, null);
        }

        private FactoryBinding join(FactoryBinding other) {
            if (other == null || kind != BindingKind.CONCRETE || other.kind != BindingKind.CONCRETE
                    || !factory.identity.equals(other.factory.identity)) {
                return unknown();
            }
            return concrete(factory.join(other.factory));
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof FactoryBinding binding
                    && kind == binding.kind
                    && Objects.equals(factory, binding.factory);
        }

        @Override
        public int hashCode() {
            return Objects.hash(kind, factory);
        }
    }

    private static final class BuilderBinding {
        private final BindingKind kind;
        private final BuilderInstance builder;

        private BuilderBinding(BindingKind kind, BuilderInstance builder) {
            this.kind = kind;
            this.builder = builder;
        }

        private static BuilderBinding concrete(BuilderInstance builder) {
            return new BuilderBinding(BindingKind.CONCRETE, builder);
        }

        private static BuilderBinding unknown() {
            return new BuilderBinding(BindingKind.UNKNOWN, null);
        }

        private BuilderBinding join(BuilderBinding other) {
            if (other == null || kind != BindingKind.CONCRETE || other.kind != BindingKind.CONCRETE
                    || !builder.identity.equals(other.builder.identity)
                    || !builder.factoryIdentity.equals(other.builder.factoryIdentity)) {
                return unknown();
            }
            return concrete(builder.join(other.builder));
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof BuilderBinding binding
                    && kind == binding.kind
                    && Objects.equals(builder, binding.builder);
        }

        @Override
        public int hashCode() {
            return Objects.hash(kind, builder);
        }
    }

    private record AnalysisState(
            Map<VariableSymbol, FactoryBinding> factories,
            Map<VariableSymbol, BuilderBinding> builders) {
        private AnalysisState {
            factories = Map.copyOf(factories);
            builders = Map.copyOf(builders);
        }

        private static AnalysisState empty() {
            return new AnalysisState(Map.of(), Map.of());
        }

        private AnalysisState join(AnalysisState other) {
            Map<VariableSymbol, FactoryBinding> mergedFactories = joinMaps(
                    factories, other.factories, FactoryBinding::join, FactoryBinding::unknown);
            Map<VariableSymbol, BuilderBinding> mergedBuilders = joinMaps(
                    builders, other.builders, BuilderBinding::join, BuilderBinding::unknown);
            return new AnalysisState(mergedFactories, mergedBuilders);
        }

        private static <T> Map<VariableSymbol, T> joinMaps(
                Map<VariableSymbol, T> left,
                Map<VariableSymbol, T> right,
                java.util.function.BiFunction<T, T, T> joiner,
                java.util.function.Supplier<T> unknown) {
            LinkedHashMap<VariableSymbol, T> result = new LinkedHashMap<>();
            LinkedHashSet<VariableSymbol> symbols = new LinkedHashSet<>(left.keySet());
            symbols.addAll(right.keySet());
            for (VariableSymbol symbol : symbols) {
                T leftValue = left.get(symbol);
                T rightValue = right.get(symbol);
                result.put(symbol, leftValue == null || rightValue == null
                        ? unknown.get()
                        : joiner.apply(leftValue, rightValue));
            }
            return result;
        }
    }

    private static final class MutableState {
        private final Map<VariableSymbol, FactoryBinding> factories;
        private final Map<VariableSymbol, BuilderBinding> builders;

        private MutableState(AnalysisState state) {
            factories = new LinkedHashMap<>(state.factories);
            builders = new LinkedHashMap<>(state.builders);
        }

        private AnalysisState freeze() {
            return new AnalysisState(factories, builders);
        }
    }

    private static final class AnalysisContext {
        private final DataFlowResult dataFlow;
        private final CallSiteContextResolver calls;
        private final Map<VariableKey, VariableSymbol> symbols;

        private AnalysisContext(DataFlowResult dataFlow, CallSiteContextResolver calls) {
            this.dataFlow = dataFlow;
            this.calls = calls;
            this.symbols = new HashMap<>();
            dataFlow.symbols().forEach(symbol -> symbols.put(
                    new VariableKey(symbol.name(), symbol.declarationLocation()), symbol));
        }

        private Optional<VariableSymbol> symbol(VariableInfo variable) {
            return Optional.ofNullable(symbols.get(new VariableKey(variable.name(), variable.location())));
        }

        private Optional<VariableSymbol> symbol(VariableReference reference) {
            return dataFlow.resolvedSymbol(reference);
        }
    }

    private record VariableKey(String name, SourceLocation location) {}
}
