package com.totalsecurity.sast.detector.deserialization;

import com.totalsecurity.sast.cfg.BasicBlock;
import com.totalsecurity.sast.cfg.ControlFlowGraph;
import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.VariableSymbol;
import com.totalsecurity.sast.finding.DeserializationEvidence;
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
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.rule.context.CallSiteContextResolver;
import com.totalsecurity.sast.taint.TaintState;
import com.totalsecurity.sast.taint.TaintValue;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Flow-sensitive direct-object-lineage analysis for supported Java native input streams. Generic
 * object-creation taint remains unchanged; only exact constructors listed here propagate lineage.
 */
public final class JavaObjectDeserializationAnalyzer {
    public static final String OBJECT_INPUT_STREAM = "java.io.ObjectInputStream";
    public static final String BYTE_ARRAY_INPUT_STREAM = "java.io.ByteArrayInputStream";
    public static final String BUFFERED_INPUT_STREAM = "java.io.BufferedInputStream";
    public static final String INPUT_STREAM = "java.io.InputStream";
    private static final String SERVLET_REQUEST = "jakarta.servlet.http.HttpServletRequest";

    public List<NativeDeserializationUse> analyze(
            JavaFileInfo file,
            ClassInfo enclosingClass,
            MethodInfo method,
            RuleAwareTaintResult analysis) {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(enclosingClass, "enclosingClass");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(analysis, "analysis");
        DataFlowResult dataFlow = analysis.taintResult().dataFlow();
        if (!dataFlow.graph().method().equals(method)) {
            throw new IllegalArgumentException("RuleAwareTaintResult belongs to a different method");
        }

        AnalysisContext context = new AnalysisContext(
                analysis,
                new CallSiteContextResolver(file, enclosingClass, method, dataFlow));
        Map<BasicBlock, AnalysisState> inStates = solve(dataFlow.graph(), context);
        LinkedHashMap<SourceLocation, NativeDeserializationUse> uses = new LinkedHashMap<>();
        for (BasicBlock block : dataFlow.graph().blocks()) {
            AnalysisState incoming = inStates.get(block);
            if (incoming == null || !dataFlow.graph().reachableBlocks().contains(block)) {
                continue;
            }
            transfer(block, incoming, context, use -> uses.merge(
                    use.readObjectLocation(), use, JavaObjectDeserializationAnalyzer::mergeUse));
        }
        return uses.values().stream()
                .sorted(Comparator.comparingInt(use -> use.readObjectLocation().startLine()))
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
                List<AnalysisState> predecessors = graph.predecessors(block).stream()
                        .map(outStates::get)
                        .filter(Objects::nonNull)
                        .toList();
                if (predecessors.isEmpty()) {
                    continue;
                }
                incoming = predecessors.getFirst();
                for (int index = 1; index < predecessors.size(); index++) {
                    incoming = incoming.join(predecessors.get(index));
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
            java.util.function.Consumer<NativeDeserializationUse> consumer) {
        MutableState state = new MutableState(incoming);
        for (Statement statement : block.statements()) {
            processStatement(statement, state, context, consumer);
        }
        block.controlStatement().ifPresent(statement ->
                controlExpression(statement).ifPresent(expression ->
                        processExpression(expression, state, context, consumer)));
        return state.freeze();
    }

    private static void processStatement(
            Statement statement,
            MutableState state,
            AnalysisContext context,
            java.util.function.Consumer<NativeDeserializationUse> consumer) {
        switch (statement) {
            case VariableDeclarationStatement declaration -> {
                for (VariableInfo variable : declaration.variables()) {
                    variable.initializer().ifPresent(expression ->
                            processExpression(expression, state, context, consumer));
                    context.symbol(variable).ifPresent(symbol ->
                            bind(symbol, variable.initializer(), state, context));
                }
            }
            case ExpressionStatement expression ->
                    processExpression(expression.expression(), state, context, consumer);
            case ReturnStatement returned -> returned.expression().ifPresent(expression ->
                    processExpression(expression, state, context, consumer));
            case ThrowStatement thrown ->
                    processExpression(thrown.expression(), state, context, consumer);
            default -> {
                // Nested control statements are represented by their own CFG blocks.
            }
        }
    }

    private static void processExpression(
            Expression expression,
            MutableState state,
            AnalysisContext context,
            java.util.function.Consumer<NativeDeserializationUse> consumer) {
        switch (expression) {
            case VariableReference ignored -> {
            }
            case Literal ignored -> {
            }
            case UnknownExpression ignored -> {
            }
            case BinaryExpression binary -> {
                processExpression(binary.left(), state, context, consumer);
                processExpression(binary.right(), state, context, consumer);
            }
            case AssignmentExpression assignment -> {
                AssignmentInfo info = assignment.assignment();
                processExpression(info.left(), state, context, consumer);
                processExpression(info.right(), state, context, consumer);
                if (info.left() instanceof VariableReference reference) {
                    context.symbol(reference).ifPresent(symbol -> bind(
                            symbol,
                            info.operator().equals("=")
                                    ? Optional.of(info.right())
                                    : Optional.empty(),
                            state,
                            context));
                }
            }
            case MethodCallExpression call -> {
                call.call().receiver().ifPresent(receiver ->
                        processExpression(receiver, state, context, consumer));
                call.call().arguments().forEach(argument ->
                        processExpression(argument, state, context, consumer));
                readObjectUse(call, state, context).ifPresent(consumer);
            }
            case ObjectCreationExpression creation -> creation.arguments().forEach(argument ->
                    processExpression(argument, state, context, consumer));
            case FieldAccessExpression field ->
                    processExpression(field.target(), state, context, consumer);
            case ParenthesizedExpression parenthesized ->
                    processExpression(parenthesized.expression(), state, context, consumer);
        }
    }

    private static void bind(
            VariableSymbol symbol,
            Optional<Expression> assigned,
            MutableState state,
            AnalysisContext context) {
        Optional<String> type = context.calls.types().qualifyType(symbol.declaredType());
        if (type.filter(OBJECT_INPUT_STREAM::equals).isPresent()) {
            state.objectStreams.put(symbol, assigned
                    .map(expression -> evaluateObjectStream(expression, state, context))
                    .orElseGet(ObjectStreamBinding::unknownBinding));
            return;
        }
        if (type.filter(JavaObjectDeserializationAnalyzer::isTrackedInputStreamType).isPresent()) {
            state.inputStreams.put(symbol, assigned
                    .map(expression -> evaluateInputStream(expression, state, context))
                    .orElseGet(InputStreamBinding::unknownBinding));
        }
    }

    private static InputStreamBinding evaluateInputStream(
            Expression expression, MutableState state, AnalysisContext context) {
        Expression unwrapped = unwrap(expression);
        if (unwrapped instanceof VariableReference reference) {
            return context.symbol(reference)
                    .map(state.inputStreams::get)
                    .filter(Objects::nonNull)
                    .orElseGet(InputStreamBinding::unknownBinding);
        }
        if (unwrapped instanceof MethodCallExpression call) {
            CallSiteContext callContext = context.calls.resolve(call);
            if (isServletInputStream(callContext)) {
                return InputStreamBinding.concrete(new StreamLineage(
                        context.taint(call),
                        call,
                        List.of(new DeserializationEvidence(
                                SERVLET_REQUEST + ".getInputStream",
                                "External servlet request body stream",
                                call.location()))));
            }
            return InputStreamBinding.unknownBinding();
        }
        if (!(unwrapped instanceof ObjectCreationExpression creation)) {
            return InputStreamBinding.unknownBinding();
        }
        Optional<String> type = context.calls.types().qualifyType(creation.typeName());
        if (type.filter(BYTE_ARRAY_INPUT_STREAM::equals).isPresent()) {
            if (creation.arguments().size() != 1
                    || context.calls.qualifiedTypeShapeOf(creation.arguments().getFirst())
                            .filter("byte[]"::equals)
                            .isEmpty()) {
                return InputStreamBinding.unknownBinding();
            }
            Expression bytes = creation.arguments().getFirst();
            return InputStreamBinding.concrete(new StreamLineage(
                    context.taint(bytes),
                    bytes,
                    List.of(new DeserializationEvidence(
                            BYTE_ARRAY_INPUT_STREAM + ".<init>(byte[])",
                            "Byte array converted to an input stream",
                            creation.location()))));
        }
        if (type.filter(BUFFERED_INPUT_STREAM::equals).isPresent()) {
            if (!supportedBufferedSignature(creation, context)) {
                return InputStreamBinding.unknownBinding();
            }
            InputStreamBinding upstream =
                    evaluateInputStream(creation.arguments().getFirst(), state, context);
            return upstream.append(new DeserializationEvidence(
                    BUFFERED_INPUT_STREAM + ".<init>",
                    "Transparent supported input-stream wrapper",
                    creation.location()));
        }
        return InputStreamBinding.unknownBinding();
    }

    private static ObjectStreamBinding evaluateObjectStream(
            Expression expression, MutableState state, AnalysisContext context) {
        Expression unwrapped = unwrap(expression);
        if (unwrapped instanceof VariableReference reference) {
            return context.symbol(reference)
                    .map(state.objectStreams::get)
                    .filter(Objects::nonNull)
                    .orElseGet(ObjectStreamBinding::unknownBinding);
        }
        if (!(unwrapped instanceof ObjectCreationExpression creation)
                || context.calls.types().qualifyType(creation.typeName())
                        .filter(OBJECT_INPUT_STREAM::equals)
                        .isEmpty()
                || creation.arguments().size() != 1) {
            return ObjectStreamBinding.unknownBinding();
        }
        InputStreamBinding input =
                evaluateInputStream(creation.arguments().getFirst(), state, context);
        DeserializationEvidence construction = new DeserializationEvidence(
                OBJECT_INPUT_STREAM + ".<init>(InputStream)",
                "Java native object-input stream construction",
                creation.location());
        LinkedHashSet<StreamLineage> lineages = new LinkedHashSet<>();
        for (StreamLineage lineage : input.lineages) {
            lineages.add(lineage.append(construction));
        }
        return ObjectStreamBinding.concrete(new ObjectStreamInstance(
                creation.location(), lineages, input.unknown));
    }

    private static Optional<NativeDeserializationUse> readObjectUse(
            MethodCallExpression call, MutableState state, AnalysisContext context) {
        CallSiteContext callContext = context.calls.resolve(call);
        if (callContext.receiverQualifiedType().filter(OBJECT_INPUT_STREAM::equals).isEmpty()
                || !callContext.methodName().equals("readObject")
                || callContext.argumentCount() != 0
                || callContext.receiver().isEmpty()) {
            return Optional.empty();
        }
        ObjectStreamBinding binding = evaluateObjectStream(
                callContext.receiver().orElseThrow(), state, context);
        LinkedHashSet<DeserializationLineage> lineages = new LinkedHashSet<>();
        TaintState inputState = binding.unknown ? TaintState.UNKNOWN : TaintState.CLEAN;
        for (ObjectStreamInstance instance : binding.instances) {
            if (instance.unknownInput) {
                inputState = inputState.join(TaintState.UNKNOWN);
            }
            for (StreamLineage lineage : instance.lineages) {
                inputState = inputState.join(lineage.taint.state());
                lineages.add(new DeserializationLineage(
                        lineage.taint,
                        lineage.endpoint,
                        lineage.evidence,
                        instance.creationLocation));
            }
        }
        return Optional.of(new NativeDeserializationUse(
                inputState, List.copyOf(lineages), call.location()));
    }

    private static boolean supportedBufferedSignature(
            ObjectCreationExpression creation, AnalysisContext context) {
        if (creation.arguments().size() == 1) {
            return true;
        }
        return creation.arguments().size() == 2
                && context.calls.qualifiedTypeShapeOf(creation.arguments().get(1))
                        .filter("int"::equals)
                        .isPresent();
    }

    private static boolean isServletInputStream(CallSiteContext call) {
        return call.receiverQualifiedType().filter(SERVLET_REQUEST::equals).isPresent()
                && call.methodName().equals("getInputStream")
                && call.argumentCount() == 0;
    }

    private static boolean isTrackedInputStreamType(String type) {
        return type.equals(INPUT_STREAM)
                || type.equals(BYTE_ARRAY_INPUT_STREAM)
                || type.equals(BUFFERED_INPUT_STREAM);
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

    private static Expression unwrap(Expression expression) {
        Expression current = expression;
        while (current instanceof ParenthesizedExpression parenthesized) {
            current = parenthesized.expression();
        }
        if (current instanceof AssignmentExpression assignment
                && assignment.assignment().operator().equals("=")) {
            return unwrap(assignment.assignment().right());
        }
        return current;
    }

    private static NativeDeserializationUse mergeUse(
            NativeDeserializationUse left, NativeDeserializationUse right) {
        LinkedHashSet<DeserializationLineage> lineages =
                new LinkedHashSet<>(left.lineages());
        lineages.addAll(right.lineages());
        return new NativeDeserializationUse(
                left.inputState().join(right.inputState()),
                List.copyOf(lineages),
                left.readObjectLocation());
    }

    private record StreamLineage(
            TaintValue taint,
            Expression endpoint,
            List<DeserializationEvidence> evidence) {
        private StreamLineage {
            Objects.requireNonNull(taint, "taint");
            Objects.requireNonNull(endpoint, "endpoint");
            evidence = List.copyOf(evidence);
        }

        private StreamLineage append(DeserializationEvidence step) {
            if (evidence.contains(step)) {
                return this;
            }
            ArrayList<DeserializationEvidence> updated = new ArrayList<>(evidence);
            updated.add(step);
            return new StreamLineage(taint, endpoint, updated);
        }
    }

    private record InputStreamBinding(Set<StreamLineage> lineages, boolean unknown) {
        private InputStreamBinding {
            lineages = Set.copyOf(lineages);
        }

        private static InputStreamBinding concrete(StreamLineage lineage) {
            return new InputStreamBinding(Set.of(lineage), false);
        }

        private static InputStreamBinding unknownBinding() {
            return new InputStreamBinding(Set.of(), true);
        }

        private InputStreamBinding join(InputStreamBinding other) {
            LinkedHashSet<StreamLineage> merged = new LinkedHashSet<>(lineages);
            merged.addAll(other.lineages);
            return new InputStreamBinding(merged, unknown || other.unknown);
        }

        private InputStreamBinding append(DeserializationEvidence step) {
            LinkedHashSet<StreamLineage> updated = new LinkedHashSet<>();
            lineages.forEach(lineage -> updated.add(lineage.append(step)));
            return new InputStreamBinding(updated, unknown);
        }

        private InputStreamBinding withUnknown() {
            return new InputStreamBinding(lineages, true);
        }
    }

    private record ObjectStreamInstance(
            SourceLocation creationLocation,
            Set<StreamLineage> lineages,
            boolean unknownInput) {
        private ObjectStreamInstance {
            Objects.requireNonNull(creationLocation, "creationLocation");
            lineages = Set.copyOf(lineages);
        }

        private ObjectStreamInstance join(ObjectStreamInstance other) {
            LinkedHashSet<StreamLineage> merged = new LinkedHashSet<>(lineages);
            merged.addAll(other.lineages);
            return new ObjectStreamInstance(
                    creationLocation, merged, unknownInput || other.unknownInput);
        }
    }

    private record ObjectStreamBinding(Set<ObjectStreamInstance> instances, boolean unknown) {
        private ObjectStreamBinding {
            instances = Set.copyOf(instances);
        }

        private static ObjectStreamBinding concrete(ObjectStreamInstance instance) {
            return new ObjectStreamBinding(Set.of(instance), false);
        }

        private static ObjectStreamBinding unknownBinding() {
            return new ObjectStreamBinding(Set.of(), true);
        }

        private ObjectStreamBinding join(ObjectStreamBinding other) {
            LinkedHashMap<SourceLocation, ObjectStreamInstance> merged = new LinkedHashMap<>();
            instances.forEach(instance -> merged.put(instance.creationLocation, instance));
            for (ObjectStreamInstance instance : other.instances) {
                merged.merge(instance.creationLocation, instance, ObjectStreamInstance::join);
            }
            return new ObjectStreamBinding(
                    new LinkedHashSet<>(merged.values()), unknown || other.unknown);
        }

        private ObjectStreamBinding withUnknown() {
            return new ObjectStreamBinding(instances, true);
        }
    }

    private record AnalysisState(
            Map<VariableSymbol, InputStreamBinding> inputStreams,
            Map<VariableSymbol, ObjectStreamBinding> objectStreams) {
        private AnalysisState {
            inputStreams = Map.copyOf(inputStreams);
            objectStreams = Map.copyOf(objectStreams);
        }

        private static AnalysisState empty() {
            return new AnalysisState(Map.of(), Map.of());
        }

        private AnalysisState join(AnalysisState other) {
            return new AnalysisState(
                    joinInputMaps(inputStreams, other.inputStreams),
                    joinObjectMaps(objectStreams, other.objectStreams));
        }

        private static Map<VariableSymbol, InputStreamBinding> joinInputMaps(
                Map<VariableSymbol, InputStreamBinding> left,
                Map<VariableSymbol, InputStreamBinding> right) {
            LinkedHashMap<VariableSymbol, InputStreamBinding> result = new LinkedHashMap<>();
            LinkedHashSet<VariableSymbol> symbols = new LinkedHashSet<>(left.keySet());
            symbols.addAll(right.keySet());
            for (VariableSymbol symbol : symbols) {
                InputStreamBinding leftValue = left.get(symbol);
                InputStreamBinding rightValue = right.get(symbol);
                if (leftValue == null) {
                    result.put(symbol, rightValue.withUnknown());
                } else if (rightValue == null) {
                    result.put(symbol, leftValue.withUnknown());
                } else {
                    result.put(symbol, leftValue.join(rightValue));
                }
            }
            return result;
        }

        private static Map<VariableSymbol, ObjectStreamBinding> joinObjectMaps(
                Map<VariableSymbol, ObjectStreamBinding> left,
                Map<VariableSymbol, ObjectStreamBinding> right) {
            LinkedHashMap<VariableSymbol, ObjectStreamBinding> result = new LinkedHashMap<>();
            LinkedHashSet<VariableSymbol> symbols = new LinkedHashSet<>(left.keySet());
            symbols.addAll(right.keySet());
            for (VariableSymbol symbol : symbols) {
                ObjectStreamBinding leftValue = left.get(symbol);
                ObjectStreamBinding rightValue = right.get(symbol);
                if (leftValue == null) {
                    result.put(symbol, rightValue.withUnknown());
                } else if (rightValue == null) {
                    result.put(symbol, leftValue.withUnknown());
                } else {
                    result.put(symbol, leftValue.join(rightValue));
                }
            }
            return result;
        }
    }

    private static final class MutableState {
        private final Map<VariableSymbol, InputStreamBinding> inputStreams;
        private final Map<VariableSymbol, ObjectStreamBinding> objectStreams;

        private MutableState(AnalysisState state) {
            inputStreams = new LinkedHashMap<>(state.inputStreams);
            objectStreams = new LinkedHashMap<>(state.objectStreams);
        }

        private AnalysisState freeze() {
            return new AnalysisState(inputStreams, objectStreams);
        }
    }

    private static final class AnalysisContext {
        private final RuleAwareTaintResult analysis;
        private final DataFlowResult dataFlow;
        private final CallSiteContextResolver calls;
        private final Map<VariableKey, VariableSymbol> symbols = new HashMap<>();

        private AnalysisContext(
                RuleAwareTaintResult analysis, CallSiteContextResolver calls) {
            this.analysis = analysis;
            this.dataFlow = analysis.taintResult().dataFlow();
            this.calls = calls;
            dataFlow.symbols().forEach(symbol -> symbols.put(
                    new VariableKey(symbol.name(), symbol.declarationLocation()), symbol));
        }

        private Optional<VariableSymbol> symbol(VariableInfo variable) {
            return Optional.ofNullable(symbols.get(
                    new VariableKey(variable.name(), variable.location())));
        }

        private Optional<VariableSymbol> symbol(VariableReference reference) {
            return dataFlow.resolvedSymbol(reference);
        }

        private TaintValue taint(Expression expression) {
            try {
                return analysis.taintResult().taintOf(expression);
            } catch (IllegalArgumentException ignored) {
                return TaintValue.unknown();
            }
        }
    }

    private record VariableKey(String name, SourceLocation location) {}
}
