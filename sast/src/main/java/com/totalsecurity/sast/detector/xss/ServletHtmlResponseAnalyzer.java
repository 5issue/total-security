package com.totalsecurity.sast.detector.xss;

import com.totalsecurity.sast.cfg.BasicBlock;
import com.totalsecurity.sast.cfg.ControlFlowGraph;
import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.VariableSymbol;
import com.totalsecurity.sast.finding.XssEvidence;
import com.totalsecurity.sast.finding.XssEvidenceKind;
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
import com.totalsecurity.sast.rule.sink.SinkCategory;
import com.totalsecurity.sast.rule.sink.SinkMatch;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Flow-sensitive content-type state and direct response-to-PrintWriter lineage analysis. */
public final class ServletHtmlResponseAnalyzer {
    public static final String RESPONSE_TYPE = "jakarta.servlet.http.HttpServletResponse";
    public static final String WRITER_TYPE = "java.io.PrintWriter";

    public List<HtmlResponseOutput> analyze(
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
                dataFlow,
                new CallSiteContextResolver(file, enclosingClass, method, dataFlow),
                new HtmlOutputSafetyAnalysis(file, enclosingClass, method, analysis),
                analysis.sinkMatches());
        Map<BasicBlock, AnalysisState> inStates = solve(dataFlow.graph(), context);
        LinkedHashMap<OutputKey, HtmlResponseOutput> outputs = new LinkedHashMap<>();
        for (BasicBlock block : dataFlow.graph().blocks()) {
            AnalysisState incoming = inStates.get(block);
            if (incoming == null || !dataFlow.graph().reachableBlocks().contains(block)) {
                continue;
            }
            transfer(block, incoming, context, output -> outputs.putIfAbsent(
                    new OutputKey(output.sink().location(), output.argumentIndex()), output));
        }
        return List.copyOf(outputs.values());
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
            java.util.function.Consumer<HtmlResponseOutput> consumer) {
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
            java.util.function.Consumer<HtmlResponseOutput> consumer) {
        switch (statement) {
            case VariableDeclarationStatement declaration -> {
                for (VariableInfo variable : declaration.variables()) {
                    variable.initializer().ifPresent(expression ->
                            processExpression(expression, state, context, consumer));
                    context.symbol(variable).ifPresent(symbol ->
                            bindWriter(symbol, variable.initializer(), state, context));
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
            java.util.function.Consumer<HtmlResponseOutput> consumer) {
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
                    context.symbol(reference).ifPresent(symbol -> bindWriter(
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
                applyContentType(call, state, context);
                output(call, state, context).ifPresent(consumer);
            }
            case ObjectCreationExpression creation -> creation.arguments().forEach(argument ->
                    processExpression(argument, state, context, consumer));
            case FieldAccessExpression field ->
                    processExpression(field.target(), state, context, consumer);
            case ParenthesizedExpression parenthesized ->
                    processExpression(parenthesized.expression(), state, context, consumer);
        }
    }

    private static void bindWriter(
            VariableSymbol symbol,
            Optional<Expression> assigned,
            MutableState state,
            AnalysisContext context) {
        if (context.calls.types().qualifyType(symbol.declaredType())
                .filter(WRITER_TYPE::equals)
                .isEmpty()) {
            return;
        }
        state.writers.put(symbol, assigned
                .map(expression -> evaluateWriter(expression, state, context))
                .orElseGet(WriterBinding::unknownBinding));
    }

    private static WriterBinding evaluateWriter(
            Expression expression, MutableState state, AnalysisContext context) {
        Expression unwrapped = unwrap(expression);
        if (unwrapped instanceof VariableReference reference) {
            return context.symbol(reference)
                    .map(state.writers::get)
                    .filter(Objects::nonNull)
                    .orElseGet(WriterBinding::unknownBinding);
        }
        if (!(unwrapped instanceof MethodCallExpression call)) {
            return WriterBinding.unknownBinding();
        }
        CallSiteContext callContext = context.calls.resolve(call);
        if (callContext.receiverQualifiedType().filter(RESPONSE_TYPE::equals).isEmpty()
                || !callContext.methodName().equals("getWriter")
                || callContext.argumentCount() != 0
                || callContext.receiver().isEmpty()) {
            return WriterBinding.unknownBinding();
        }
        return responseSymbol(callContext.receiver().orElseThrow(), context)
                .map(response -> WriterBinding.concrete(
                        new WriterOrigin(response, call.location())))
                .orElseGet(WriterBinding::unknownBinding);
    }

    private static void applyContentType(
            MethodCallExpression call, MutableState state, AnalysisContext context) {
        CallSiteContext callContext = context.calls.resolve(call);
        if (callContext.receiverQualifiedType().filter(RESPONSE_TYPE::equals).isEmpty()
                || !callContext.methodName().equals("setContentType")
                || callContext.argumentCount() != 1
                || !callContext.argumentHasType(0, "java.lang.String")
                || callContext.receiver().isEmpty()) {
            return;
        }
        responseSymbol(callContext.receiver().orElseThrow(), context).ifPresent(response ->
                state.responses.put(response, parseContentType(
                        callContext.arguments().getFirst(), callContext.location())));
    }

    private static Optional<HtmlResponseOutput> output(
            MethodCallExpression call, MutableState state, AnalysisContext context) {
        SinkMatch sink = context.responseBodySinks.get(call);
        if (sink == null) {
            return Optional.empty();
        }
        int argumentIndex = sink.sensitiveArgumentIndexes().iterator().next();
        WriterBinding writer = call.call().receiver()
                .map(receiver -> evaluateWriter(receiver, state, context))
                .orElseGet(WriterBinding::unknownBinding);
        ResponseContent content = writerContent(writer, state);
        LinkedHashSet<XssEvidence> evidence = new LinkedHashSet<>();
        evidence.addAll(content.evidence);
        writer.origins.forEach(origin -> evidence.add(new XssEvidence(
                XssEvidenceKind.WRITER_DERIVATION,
                RESPONSE_TYPE + ".getWriter() derived this PrintWriter",
                origin.derivationLocation)));
        evidence.add(new XssEvidence(
                XssEvidenceKind.OUTPUT,
                WRITER_TYPE + "." + call.call().methodName() + " String argument 0",
                call.location()));
        return Optional.of(new HtmlResponseOutput(
                sink,
                argumentIndex,
                !writer.unknown && !writer.origins.isEmpty(),
                content.state,
                context.outputSafety.classify(call.call().arguments().get(argumentIndex)),
                List.copyOf(evidence)));
    }

    private static ResponseContent writerContent(WriterBinding writer, MutableState state) {
        if (writer.unknown || writer.origins.isEmpty()) {
            return ResponseContent.unknown();
        }
        ResponseContent merged = null;
        for (WriterOrigin origin : writer.origins) {
            ResponseContent value = state.responses.getOrDefault(
                    origin.response, ResponseContent.unset());
            merged = merged == null ? value : merged.join(value);
        }
        return merged == null ? ResponseContent.unknown() : merged;
    }

    private static ResponseContent parseContentType(
            Expression expression, SourceLocation location) {
        Expression unwrapped = unwrap(expression);
        if (!(unwrapped instanceof Literal literal)
                || !literal.kind().equals("string_literal")) {
            return ResponseContent.unknown();
        }
        Optional<String> decoded = decodeStringLiteral(literal.source());
        if (decoded.isEmpty()) {
            return ResponseContent.unknown();
        }
        String configured = decoded.orElseThrow();
        String mediaType = configured.split(";", 2)[0].trim();
        if (!mediaType.equalsIgnoreCase("text/html")) {
            return ResponseContent.nonHtml();
        }
        return ResponseContent.html(new XssEvidence(
                XssEvidenceKind.CONTENT_TYPE,
                RESPONSE_TYPE + ".setContentType explicitly configured " + configured,
                location));
    }

    private static Optional<String> decodeStringLiteral(String source) {
        if (source.length() < 2 || source.charAt(0) != '"'
                || source.charAt(source.length() - 1) != '"') {
            return Optional.empty();
        }
        String body = source.substring(1, source.length() - 1);
        StringBuilder decoded = new StringBuilder(body.length());
        boolean escaping = false;
        for (int index = 0; index < body.length(); index++) {
            char current = body.charAt(index);
            if (!escaping && current == '\\') {
                escaping = true;
                continue;
            }
            if (!escaping) {
                decoded.append(current);
                continue;
            }
            decoded.append(switch (current) {
                case 't' -> '\t';
                case 'n' -> '\n';
                case 'r' -> '\r';
                case 'b' -> '\b';
                case 'f' -> '\f';
                case '"' -> '"';
                case '\'' -> '\'';
                case '\\' -> '\\';
                default -> current;
            });
            escaping = false;
        }
        return escaping ? Optional.empty() : Optional.of(decoded.toString());
    }

    private static Optional<VariableSymbol> responseSymbol(
            Expression expression, AnalysisContext context) {
        Expression unwrapped = unwrap(expression);
        if (!(unwrapped instanceof VariableReference reference)) {
            return Optional.empty();
        }
        return context.symbol(reference).filter(symbol -> context.calls.types()
                .qualifyType(symbol.declaredType())
                .filter(RESPONSE_TYPE::equals)
                .isPresent());
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

    private record ResponseContent(
            HttpResponseContentType state, Set<XssEvidence> evidence) {
        private ResponseContent {
            Objects.requireNonNull(state, "state");
            evidence = Set.copyOf(evidence);
            if (state != HttpResponseContentType.HTML && !evidence.isEmpty()) {
                throw new IllegalArgumentException("Only proven HTML state carries evidence");
            }
        }

        private static ResponseContent html(XssEvidence evidence) {
            return new ResponseContent(HttpResponseContentType.HTML, Set.of(evidence));
        }

        private static ResponseContent nonHtml() {
            return new ResponseContent(HttpResponseContentType.NON_HTML, Set.of());
        }

        private static ResponseContent unknown() {
            return new ResponseContent(HttpResponseContentType.UNKNOWN, Set.of());
        }

        private static ResponseContent unset() {
            return new ResponseContent(HttpResponseContentType.UNSET, Set.of());
        }

        private ResponseContent join(ResponseContent other) {
            HttpResponseContentType joined = state.join(other.state);
            if (joined != HttpResponseContentType.HTML) {
                return switch (joined) {
                    case NON_HTML -> nonHtml();
                    case UNKNOWN -> unknown();
                    case UNSET -> unset();
                    case HTML -> throw new IllegalStateException("Unexpected HTML merge");
                };
            }
            LinkedHashSet<XssEvidence> merged = new LinkedHashSet<>(evidence);
            merged.addAll(other.evidence);
            return new ResponseContent(HttpResponseContentType.HTML, merged);
        }
    }

    private record WriterOrigin(
            VariableSymbol response, SourceLocation derivationLocation) {
        private WriterOrigin {
            Objects.requireNonNull(response, "response");
            Objects.requireNonNull(derivationLocation, "derivationLocation");
        }
    }

    private record WriterBinding(Set<WriterOrigin> origins, boolean unknown) {
        private WriterBinding {
            origins = Set.copyOf(origins);
        }

        private static WriterBinding concrete(WriterOrigin origin) {
            return new WriterBinding(Set.of(origin), false);
        }

        private static WriterBinding unknownBinding() {
            return new WriterBinding(Set.of(), true);
        }

        private WriterBinding join(WriterBinding other) {
            LinkedHashSet<WriterOrigin> merged = new LinkedHashSet<>(origins);
            merged.addAll(other.origins);
            return new WriterBinding(merged, unknown || other.unknown);
        }

        private WriterBinding withUnknown() {
            return new WriterBinding(origins, true);
        }
    }

    private record AnalysisState(
            Map<VariableSymbol, ResponseContent> responses,
            Map<VariableSymbol, WriterBinding> writers) {
        private AnalysisState {
            responses = Map.copyOf(responses);
            writers = Map.copyOf(writers);
        }

        private static AnalysisState empty() {
            return new AnalysisState(Map.of(), Map.of());
        }

        private AnalysisState join(AnalysisState other) {
            return new AnalysisState(
                    joinResponses(responses, other.responses),
                    joinWriters(writers, other.writers));
        }

        private static Map<VariableSymbol, ResponseContent> joinResponses(
                Map<VariableSymbol, ResponseContent> left,
                Map<VariableSymbol, ResponseContent> right) {
            LinkedHashMap<VariableSymbol, ResponseContent> result = new LinkedHashMap<>();
            LinkedHashSet<VariableSymbol> symbols = new LinkedHashSet<>(left.keySet());
            symbols.addAll(right.keySet());
            for (VariableSymbol symbol : symbols) {
                result.put(symbol, left.getOrDefault(symbol, ResponseContent.unset())
                        .join(right.getOrDefault(symbol, ResponseContent.unset())));
            }
            return result;
        }

        private static Map<VariableSymbol, WriterBinding> joinWriters(
                Map<VariableSymbol, WriterBinding> left,
                Map<VariableSymbol, WriterBinding> right) {
            LinkedHashMap<VariableSymbol, WriterBinding> result = new LinkedHashMap<>();
            LinkedHashSet<VariableSymbol> symbols = new LinkedHashSet<>(left.keySet());
            symbols.addAll(right.keySet());
            for (VariableSymbol symbol : symbols) {
                WriterBinding leftValue = left.get(symbol);
                WriterBinding rightValue = right.get(symbol);
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
        private final Map<VariableSymbol, ResponseContent> responses;
        private final Map<VariableSymbol, WriterBinding> writers;

        private MutableState(AnalysisState state) {
            responses = new LinkedHashMap<>(state.responses);
            writers = new LinkedHashMap<>(state.writers);
        }

        private AnalysisState freeze() {
            return new AnalysisState(responses, writers);
        }
    }

    private static final class AnalysisContext {
        private final DataFlowResult dataFlow;
        private final CallSiteContextResolver calls;
        private final HtmlOutputSafetyAnalysis outputSafety;
        private final Map<MethodCallExpression, SinkMatch> responseBodySinks =
                new IdentityHashMap<>();
        private final Map<VariableKey, VariableSymbol> symbols = new HashMap<>();

        private AnalysisContext(
                DataFlowResult dataFlow,
                CallSiteContextResolver calls,
                HtmlOutputSafetyAnalysis outputSafety,
                List<SinkMatch> sinks) {
            this.dataFlow = dataFlow;
            this.calls = calls;
            this.outputSafety = outputSafety;
            dataFlow.symbols().forEach(symbol -> symbols.put(
                    new VariableKey(symbol.name(), symbol.declarationLocation()), symbol));
            sinks.stream()
                    .filter(sink -> sink.category() == SinkCategory.HTTP_RESPONSE_BODY)
                    .forEach(sink -> responseBodySinks.put(sink.call(), sink));
        }

        private Optional<VariableSymbol> symbol(VariableInfo variable) {
            return Optional.ofNullable(symbols.get(
                    new VariableKey(variable.name(), variable.location())));
        }

        private Optional<VariableSymbol> symbol(VariableReference reference) {
            return dataFlow.resolvedSymbol(reference);
        }
    }

    private record VariableKey(String name, SourceLocation location) {}

    private record OutputKey(SourceLocation location, int argumentIndex) {}
}
