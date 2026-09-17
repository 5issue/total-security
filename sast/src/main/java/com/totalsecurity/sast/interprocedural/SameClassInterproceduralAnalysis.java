package com.totalsecurity.sast.interprocedural;

import com.totalsecurity.sast.cfg.ControlFlowGraph;
import com.totalsecurity.sast.cfg.ControlFlowGraphBuilder;
import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.Definition;
import com.totalsecurity.sast.dataflow.DefinitionKind;
import com.totalsecurity.sast.dataflow.ReachingDefinitionsAnalysis;
import com.totalsecurity.sast.detector.TaintSinkVulnerability;
import com.totalsecurity.sast.detector.command.CommandInjectionDetector;
import com.totalsecurity.sast.detector.ldap.LdapInjectionDetector;
import com.totalsecurity.sast.detector.path.PathTraversalDetector;
import com.totalsecurity.sast.detector.sql.SqlInjectionDetector;
import com.totalsecurity.sast.detector.ssrf.SsrfDetector;
import com.totalsecurity.sast.finding.Finding;
import com.totalsecurity.sast.finding.FindingFlow;
import com.totalsecurity.sast.finding.FindingFlowStep;
import com.totalsecurity.sast.finding.FindingFlowStepKind;
import com.totalsecurity.sast.finding.FindingSink;
import com.totalsecurity.sast.finding.FindingSource;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.ParameterInfo;
import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.expression.Expression;
import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import com.totalsecurity.sast.ir.statement.ReturnStatement;
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import com.totalsecurity.sast.rule.RuleRegistry;
import com.totalsecurity.sast.rule.context.CallSiteContextResolver;
import com.totalsecurity.sast.rule.sink.SinkMatch;
import com.totalsecurity.sast.rule.source.SourceMatch;
import com.totalsecurity.sast.taint.DefinitionTaintSeed;
import com.totalsecurity.sast.taint.IntraproceduralTaintAnalysis;
import com.totalsecurity.sast.taint.TaintAnalysisResult;
import com.totalsecurity.sast.taint.TaintSeed;
import com.totalsecurity.sast.taint.TaintState;
import com.totalsecurity.sast.taint.TaintValue;
import com.totalsecurity.sast.taint.model.MethodTaintModel;
import com.totalsecurity.sast.taint.model.MethodTaintModelRegistry;
import com.totalsecurity.sast.taint.model.MethodTaintSemanticsProvider;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Class-level orchestration for exact, acyclic, direct same-class taint summaries. */
public final class SameClassInterproceduralAnalysis {
    private final IntraproceduralTaintAnalysis taintAnalysis =
            new IntraproceduralTaintAnalysis();

    public SameClassInterproceduralResult analyze(
            JavaFileInfo file, ClassInfo type, RuleRegistry rules) {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(rules, "rules");

        LinkedHashMap<MethodInfo, MethodArtifacts> artifacts = prepare(file, type);
        SameClassCallResolver resolver = new SameClassCallResolver(file, type);
        List<SameClassCallResolution> initial = resolveCalls(artifacts, resolver);
        RecursionResult recursion = excludeRecursion(initial);
        List<SameClassCallResolution> resolutions = recursion.resolutions();
        LinkedHashSet<UnsupportedInterproceduralFlow> unsupported =
                new LinkedHashSet<>(recursion.unsupported());
        resolutions.stream().flatMap(item -> item.unsupported().stream()).forEach(unsupported::add);

        LinkedHashMap<MethodInfo, SameClassMethodSummary> summaries = new LinkedHashMap<>();
        for (MethodInfo method : artifacts.keySet()) {
            summarize(method, artifacts, resolutions, recursion.recursiveMethods(),
                    summaries, rules);
        }
        summaries.values().forEach(summary -> unsupported.addAll(summary.unsupported()));

        LinkedHashMap<MethodInfo, RuleAwareTaintResult> actual = new LinkedHashMap<>();
        for (Map.Entry<MethodInfo, MethodArtifacts> entry : artifacts.entrySet()) {
            MethodInfo method = entry.getKey();
            MethodArtifacts methodArtifacts = entry.getValue();
            MethodTaintSemanticsProvider semantics = semantics(
                    method, methodArtifacts, resolutions, summaries, rules);
            List<SourceMatch> sources = rules.matchSources(
                    file, type, method, methodArtifacts.dataFlow());
            List<TaintSeed> seeds = sources.stream()
                    .map(source -> source.toTaintSeed(methodArtifacts.dataFlow()))
                    .toList();
            TaintAnalysisResult taint = taintAnalysis.analyze(
                    methodArtifacts.dataFlow(), seeds, semantics);
            List<SinkMatch> sinks = rules.matchSinks(
                    file, type, method, methodArtifacts.dataFlow());
            actual.put(method, new RuleAwareTaintResult(sources, seeds, taint, sinks));
        }

        LinkedHashMap<FindingKey, Finding> findings = new LinkedHashMap<>();
        for (Map.Entry<MethodInfo, RuleAwareTaintResult> entry : actual.entrySet()) {
            List<Finding> local = localFindings(entry.getValue());
            for (Finding finding : local) {
                Finding augmented = augmentReturnBoundaries(
                        finding, entry.getKey(), entry.getValue(), resolutions, summaries);
                mergeFinding(findings, augmented);
            }
        }
        addCrossMethodFindings(findings, actual, resolutions, summaries);

        return new SameClassInterproceduralResult(
                summaries, actual, resolutions, List.copyOf(unsupported),
                findings.values().stream()
                        .sorted(Comparator.comparingInt(finding ->
                                finding.sink().location().startLine()))
                        .toList());
    }

    private static LinkedHashMap<MethodInfo, MethodArtifacts> prepare(
            JavaFileInfo file, ClassInfo type) {
        LinkedHashMap<MethodInfo, MethodArtifacts> result = new LinkedHashMap<>();
        for (MethodInfo method : type.methods()) {
            if (method.body().isEmpty()) {
                continue;
            }
            ControlFlowGraph graph = new ControlFlowGraphBuilder().build(method);
            DataFlowResult dataFlow = new ReachingDefinitionsAnalysis().analyze(graph);
            result.put(method, new MethodArtifacts(
                    file, type, dataFlow,
                    new CallSiteContextResolver(file, type, method, dataFlow)));
        }
        return result;
    }

    private static List<SameClassCallResolution> resolveCalls(
            Map<MethodInfo, MethodArtifacts> artifacts, SameClassCallResolver resolver) {
        List<SameClassCallResolution> result = new ArrayList<>();
        artifacts.forEach((method, methodArtifacts) -> methodArtifacts.calls().callSites().forEach(call ->
                resolver.resolve(method, call.call(), methodArtifacts.calls()).ifPresent(result::add)));
        return List.copyOf(result);
    }

    private static RecursionResult excludeRecursion(List<SameClassCallResolution> resolutions) {
        Map<MethodInfo, Set<MethodInfo>> adjacency = new LinkedHashMap<>();
        for (SameClassCallResolution resolution : resolutions) {
            resolution.target().ifPresent(target -> adjacency
                    .computeIfAbsent(resolution.caller(), ignored -> new LinkedHashSet<>())
                    .add(target));
        }
        Set<MethodCallExpression> recursiveCalls = java.util.Collections.newSetFromMap(
                new IdentityHashMap<>());
        LinkedHashSet<MethodInfo> recursiveMethods = new LinkedHashSet<>();
        for (SameClassCallResolution resolution : resolutions) {
            if (resolution.target().isEmpty()) {
                continue;
            }
            MethodInfo target = resolution.target().orElseThrow();
            if (target.equals(resolution.caller())
                    || reachable(target, resolution.caller(), adjacency, new LinkedHashSet<>())) {
                recursiveCalls.add(resolution.call());
                recursiveMethods.add(resolution.caller());
                recursiveMethods.add(target);
            }
        }
        List<UnsupportedInterproceduralFlow> unsupported = new ArrayList<>();
        List<SameClassCallResolution> replaced = new ArrayList<>();
        for (SameClassCallResolution resolution : resolutions) {
            if (!recursiveCalls.contains(resolution.call())) {
                replaced.add(resolution);
                continue;
            }
            UnsupportedInterproceduralFlow item = new UnsupportedInterproceduralFlow(
                    UnsupportedInterproceduralReason.RECURSIVE_CALL,
                    "Recursive same-class edge is excluded from summary expansion",
                    resolution.call().location());
            unsupported.add(item);
            replaced.add(new SameClassCallResolution(
                    resolution.caller(), resolution.call(), SameClassCallStatus.UNSUPPORTED,
                    Optional.empty(), Optional.of(item)));
        }
        return new RecursionResult(List.copyOf(replaced), Set.copyOf(recursiveMethods),
                List.copyOf(unsupported));
    }

    private static boolean reachable(
            MethodInfo current,
            MethodInfo target,
            Map<MethodInfo, Set<MethodInfo>> adjacency,
            Set<MethodInfo> visited) {
        if (!visited.add(current)) {
            return false;
        }
        if (current.equals(target)) {
            return true;
        }
        return adjacency.getOrDefault(current, Set.of()).stream()
                .anyMatch(next -> reachable(next, target, adjacency, visited));
    }

    private SameClassMethodSummary summarize(
            MethodInfo method,
            Map<MethodInfo, MethodArtifacts> artifacts,
            List<SameClassCallResolution> resolutions,
            Set<MethodInfo> recursiveMethods,
            Map<MethodInfo, SameClassMethodSummary> completed,
            RuleRegistry rules) {
        SameClassMethodSummary existing = completed.get(method);
        if (existing != null) {
            return existing;
        }
        if (recursiveMethods.contains(method)) {
            SameClassMethodSummary summary = new SameClassMethodSummary(
                    method, MethodReturnDependency.unknown(), List.of(),
                    resolutionsFor(method, resolutions).stream()
                            .flatMap(item -> item.unsupported().stream()).toList());
            completed.put(method, summary);
            return summary;
        }
        for (SameClassCallResolution resolution : resolutionsFor(method, resolutions)) {
            resolution.target().ifPresent(target -> summarize(
                    target, artifacts, resolutions, recursiveMethods, completed, rules));
        }
        MethodArtifacts methodArtifacts = artifacts.get(method);
        SyntheticSeeds synthetic = syntheticSeeds(method, methodArtifacts.dataFlow());
        MethodTaintSemanticsProvider semantics = semantics(
                method, methodArtifacts, resolutions, completed, rules);
        TaintAnalysisResult taint = taintAnalysis.analyze(
                methodArtifacts.dataFlow(), synthetic.seeds(), semantics);
        List<SinkMatch> sinks = rules.matchSinks(
                methodArtifacts.file(),
                methodArtifacts.type(),
                method,
                methodArtifacts.dataFlow());
        List<InterproceduralSinkDependency> dependencies = new ArrayList<>();
        addDirectSinkDependencies(dependencies, sinks, taint, synthetic);
        addTransitiveSinkDependencies(
                dependencies, method, resolutions, completed, taint, synthetic);
        SameClassMethodSummary summary = new SameClassMethodSummary(
                method,
                returnDependency(method, taint, synthetic, resolutions, completed),
                dependencies,
                resolutionsFor(method, resolutions).stream()
                        .flatMap(item -> item.unsupported().stream()).toList());
        completed.put(method, summary);
        return summary;
    }

    private MethodTaintSemanticsProvider semantics(
            MethodInfo method,
            MethodArtifacts artifacts,
            List<SameClassCallResolution> resolutions,
            Map<MethodInfo, SameClassMethodSummary> summaries,
            RuleRegistry rules) {
        Map<MethodCallExpression, SameClassMethodSummary> callSummaries = new IdentityHashMap<>();
        for (SameClassCallResolution resolution : resolutionsFor(method, resolutions)) {
            resolution.target().map(summaries::get).ifPresent(summary ->
                    callSummaries.put(resolution.call(), summary));
        }
        List<MethodTaintModel> models = new ArrayList<>(rules.sanitizerRules());
        models.add(new SameClassMethodTaintModel(callSummaries));
        models.addAll(rules.methodModels());
        return new MethodTaintModelRegistry(artifacts.calls(), models);
    }

    private static SyntheticSeeds syntheticSeeds(MethodInfo method, DataFlowResult dataFlow) {
        List<TaintSeed> seeds = new ArrayList<>();
        Map<TaintSeed, Integer> indexes = new LinkedHashMap<>();
        for (int index = 0; index < method.parameters().size(); index++) {
            ParameterInfo parameter = method.parameters().get(index);
            Definition definition = dataFlow.definitions().stream()
                    .filter(candidate -> candidate.kind() == DefinitionKind.PARAMETER)
                    .filter(candidate -> candidate.location().equals(parameter.location()))
                    .findFirst()
                    .orElseThrow();
            TaintSeed seed = new DefinitionTaintSeed(
                    "SAME_CLASS_PARAMETER_" + index + "@" + parameter.location().startLine(),
                    definition);
            seeds.add(seed);
            indexes.put(seed, index);
        }
        return new SyntheticSeeds(List.copyOf(seeds), Map.copyOf(indexes));
    }

    private static MethodReturnDependency returnDependency(
            MethodInfo method,
            TaintAnalysisResult taint,
            SyntheticSeeds synthetic,
            List<SameClassCallResolution> resolutions,
            Map<MethodInfo, SameClassMethodSummary> summaries) {
        LinkedHashSet<Integer> indexes = new LinkedHashSet<>();
        LinkedHashMap<Integer, List<FindingFlowStep>> flows = new LinkedHashMap<>();
        boolean unknown = false;
        boolean sawValue = false;
        for (ReturnExpression returned : reachableReturns(taint)) {
            sawValue = true;
            Expression expression = returned.expression();
            TaintValue value = taint.taintOf(expression);
            if (value.state() == TaintState.UNKNOWN) {
                unknown = true;
            }
            for (TaintSeed origin : value.origins()) {
                Integer index = synthetic.indexes().get(origin);
                if (index == null) {
                    continue;
                }
                indexes.add(index);
                List<FindingFlowStep> path = new ArrayList<>(expandReturnBoundaries(
                        method,
                        taint,
                        origin,
                        InterproceduralFlowSupport.syntheticFlowTo(taint, expression, origin),
                        resolutions,
                        summaries));
                path.add(new FindingFlowStep(
                        FindingFlowStepKind.METHOD_RETURN,
                        returned.location(),
                        "Return from " + method.name()));
                flows.putIfAbsent(index, List.copyOf(path));
            }
        }
        if (!indexes.isEmpty()) {
            return new MethodReturnDependency(
                    MethodReturnDependencyKind.PARAMETER_DEPENDENT, indexes, flows);
        }
        return sawValue && !unknown ? MethodReturnDependency.clean() : MethodReturnDependency.unknown();
    }

    private static List<ReturnExpression> reachableReturns(TaintAnalysisResult taint) {
        List<ReturnExpression> returns = new ArrayList<>();
        for (var block : taint.dataFlow().graph().blocks()) {
            if (!taint.dataFlow().graph().reachableBlocks().contains(block)) {
                continue;
            }
            for (var statement : block.statements()) {
                if (statement instanceof ReturnStatement returned
                        && returned.expression().isPresent()) {
                    returns.add(new ReturnExpression(
                            returned.expression().orElseThrow(), returned.location()));
                }
            }
        }
        return List.copyOf(returns);
    }

    private static void addDirectSinkDependencies(
            List<InterproceduralSinkDependency> output,
            List<SinkMatch> sinks,
            TaintAnalysisResult taint,
            SyntheticSeeds synthetic) {
        for (SinkMatch sink : sinks) {
            if (TaintSinkVulnerability.forCategory(sink.category()).isEmpty()) {
                continue;
            }
            for (int argumentIndex : sink.sensitiveArgumentIndexes()) {
                Expression argument = sink.call().call().arguments().get(argumentIndex);
                TaintValue value = taint.argumentTaint(sink.call(), argumentIndex);
                LinkedHashSet<Integer> indexes = new LinkedHashSet<>();
                LinkedHashMap<Integer, List<FindingFlowStep>> flows = new LinkedHashMap<>();
                for (TaintSeed origin : value.origins()) {
                    Integer index = synthetic.indexes().get(origin);
                    if (index != null) {
                        indexes.add(index);
                        flows.putIfAbsent(index,
                                InterproceduralFlowSupport.syntheticFlowTo(taint, argument, origin));
                    }
                }
                if (!indexes.isEmpty()) {
                    output.add(new InterproceduralSinkDependency(
                            sink, argumentIndex, indexes, flows, List.of()));
                }
            }
        }
    }

    private static void addTransitiveSinkDependencies(
            List<InterproceduralSinkDependency> output,
            MethodInfo method,
            List<SameClassCallResolution> resolutions,
            Map<MethodInfo, SameClassMethodSummary> summaries,
            TaintAnalysisResult taint,
            SyntheticSeeds synthetic) {
        for (SameClassCallResolution resolution : resolutionsFor(method, resolutions)) {
            if (resolution.target().isEmpty()) {
                continue;
            }
            MethodInfo target = resolution.target().orElseThrow();
            SameClassMethodSummary targetSummary = summaries.get(target);
            if (targetSummary == null) {
                continue;
            }
            for (InterproceduralSinkDependency nested : targetSummary.sinkDependencies()) {
                LinkedHashSet<Integer> callerIndexes = new LinkedHashSet<>();
                LinkedHashMap<Integer, List<FindingFlowStep>> flows = new LinkedHashMap<>();
                for (int calleeIndex : nested.parameterIndexes()) {
                    Expression argument = resolution.call().call().arguments().get(calleeIndex);
                    TaintValue value = taint.argumentTaint(resolution.call(), calleeIndex);
                    for (TaintSeed origin : value.origins()) {
                        Integer callerIndex = synthetic.indexes().get(origin);
                        if (callerIndex == null) {
                            continue;
                        }
                        callerIndexes.add(callerIndex);
                        List<FindingFlowStep> steps = new ArrayList<>(
                                InterproceduralFlowSupport.syntheticFlowTo(taint, argument, origin));
                        steps.add(callStep(method, target, resolution.call().location()));
                        steps.add(bindingStep(target, calleeIndex));
                        steps.addAll(nested.parameterFlows().getOrDefault(calleeIndex, List.of()));
                        flows.putIfAbsent(callerIndex, List.copyOf(steps));
                    }
                }
                if (!callerIndexes.isEmpty()) {
                    List<InterproceduralCallBoundary> chain = new ArrayList<>();
                    chain.add(new InterproceduralCallBoundary(
                            method, target, resolution.call().location(), nested.parameterIndexes()));
                    chain.addAll(nested.callChain());
                    output.add(new InterproceduralSinkDependency(
                            nested.sink(), nested.argumentIndex(), callerIndexes, flows, chain));
                }
            }
        }
    }

    private static void addCrossMethodFindings(
            Map<FindingKey, Finding> findings,
            Map<MethodInfo, RuleAwareTaintResult> actual,
            List<SameClassCallResolution> resolutions,
            Map<MethodInfo, SameClassMethodSummary> summaries) {
        for (SameClassCallResolution resolution : resolutions) {
            if (resolution.target().isEmpty()) {
                continue;
            }
            RuleAwareTaintResult callerAnalysis = actual.get(resolution.caller());
            SameClassMethodSummary target = summaries.get(resolution.target().orElseThrow());
            if (callerAnalysis == null || target == null) {
                continue;
            }
            for (InterproceduralSinkDependency dependency : target.sinkDependencies()) {
                TaintSinkVulnerability spec = TaintSinkVulnerability
                        .forCategory(dependency.sink().category()).orElseThrow();
                for (int parameterIndex : dependency.parameterIndexes()) {
                    Expression argument = resolution.call().call().arguments().get(parameterIndex);
                    TaintValue value = callerAnalysis.taintResult()
                            .argumentTaint(resolution.call(), parameterIndex);
                    if (value.state() != TaintState.TAINTED) {
                        continue;
                    }
                    for (TaintSeed origin : value.origins()) {
                        SourceMatch match = callerAnalysis.sourceMatch(origin).orElse(null);
                        if (match == null) {
                            continue;
                        }
                        FindingSource source = InterproceduralFlowSupport.source(match, origin);
                        List<FindingFlowStep> steps = new ArrayList<>(
                                InterproceduralFlowSupport.flowTo(
                                        callerAnalysis.taintResult(), argument, origin, source));
                        steps.add(callStep(
                                resolution.caller(), resolution.target().orElseThrow(),
                                resolution.call().location()));
                        steps.add(bindingStep(resolution.target().orElseThrow(), parameterIndex));
                        steps.addAll(dependency.parameterFlows()
                                .getOrDefault(parameterIndex, List.of()));
                        steps.add(sinkStep(dependency.sink(), dependency.argumentIndex()));
                        Finding finding = new Finding(
                                spec.ruleId(), spec.vulnerabilityType(), spec.cwe(), spec.severity(),
                                dependency.sink().call().call().arguments()
                                        .get(dependency.argumentIndex()).location(),
                                List.of(source),
                                findingSink(dependency.sink(), dependency.argumentIndex()),
                                List.of(new FindingFlow(source, steps)),
                                "Tainted external input crosses a directly resolved same-class "
                                        + "call and reaches a supported " + spec.category() + " sink.");
                        mergeFinding(findings, finding);
                    }
                }
            }
        }
    }

    private static Finding augmentReturnBoundaries(
            Finding finding,
            MethodInfo method,
            RuleAwareTaintResult actual,
            List<SameClassCallResolution> resolutions,
            Map<MethodInfo, SameClassMethodSummary> summaries) {
        List<SameClassCallResolution> calls = resolutionsFor(method, resolutions).stream()
                .filter(item -> item.target().isPresent()).toList();
        if (calls.isEmpty()) {
            return finding;
        }
        List<FindingFlow> augmented = new ArrayList<>();
        for (FindingFlow flow : finding.flows()) {
            TaintSeed origin = actual.taintSeeds().stream()
                    .filter(seed -> seed.id().equals(flow.source().seedId()))
                    .findFirst().orElse(null);
            if (origin == null) {
                augmented.add(flow);
                continue;
            }
            List<FindingFlowStep> steps = expandReturnBoundaries(
                    method,
                    actual.taintResult(),
                    origin,
                    flow.steps(),
                    calls,
                    summaries);
            augmented.add(new FindingFlow(flow.source(), steps));
        }
        return new Finding(
                finding.ruleId(), finding.vulnerabilityType(), finding.cwe(), finding.severity(),
                finding.primaryLocation(), finding.sources(), finding.sink(), augmented,
                finding.evidence());
    }

    private static List<FindingFlowStep> expandReturnBoundaries(
            MethodInfo method,
            TaintAnalysisResult taint,
            TaintSeed origin,
            List<FindingFlowStep> original,
            List<SameClassCallResolution> resolutions,
            Map<MethodInfo, SameClassMethodSummary> summaries) {
        List<SameClassCallResolution> calls = resolutionsFor(method, resolutions).stream()
                .filter(item -> item.target().isPresent()).toList();
        if (calls.isEmpty()) {
            return List.copyOf(original);
        }
        List<FindingFlowStep> expanded = new ArrayList<>();
        for (FindingFlowStep step : original) {
            SameClassCallResolution boundary = calls.stream()
                    .filter(item -> item.call().location().equals(step.location()))
                    .findFirst().orElse(null);
            if (boundary != null && step.kind() == FindingFlowStepKind.EXPRESSION) {
                MethodInfo target = boundary.target().orElseThrow();
                SameClassMethodSummary summary = summaries.get(target);
                if (summary != null) {
                    int parameterIndex = matchingParameterIndex(
                            taint,
                            boundary.call(),
                            origin,
                            summary.returnDependency().parameterIndexes());
                    if (parameterIndex >= 0) {
                        expanded.add(callStep(method, target, step.location()));
                        expanded.add(bindingStep(target, parameterIndex));
                        expanded.addAll(summary.returnDependency().parameterFlows()
                                .getOrDefault(parameterIndex, List.of()));
                    }
                }
            }
            expanded.add(step);
        }
        return List.copyOf(expanded);
    }

    private static int matchingParameterIndex(
            TaintAnalysisResult taint,
            MethodCallExpression call,
            TaintSeed origin,
            Set<Integer> indexes) {
        return indexes.stream().sorted()
                .filter(index -> taint.argumentTaint(call, index)
                        .origins().contains(origin))
                .findFirst().orElse(-1);
    }

    private static List<Finding> localFindings(RuleAwareTaintResult analysis) {
        List<Finding> findings = new ArrayList<>();
        findings.addAll(new SqlInjectionDetector().detect(analysis));
        findings.addAll(new CommandInjectionDetector().detect(analysis));
        findings.addAll(new PathTraversalDetector().detect(analysis));
        findings.addAll(new SsrfDetector().detect(analysis));
        findings.addAll(new LdapInjectionDetector().detect(analysis));
        return findings;
    }

    private static FindingFlowStep callStep(
            MethodInfo caller, MethodInfo callee, SourceLocation location) {
        return new FindingFlowStep(
                FindingFlowStepKind.METHOD_CALL, location,
                "Same-class call " + caller.name() + " -> " + callee.name());
    }

    private static FindingFlowStep bindingStep(MethodInfo callee, int parameterIndex) {
        ParameterInfo parameter = callee.parameters().get(parameterIndex);
        return new FindingFlowStep(
                FindingFlowStepKind.PARAMETER_BINDING, parameter.location(),
                "Bind argument " + parameterIndex + " to " + callee.name()
                        + " parameter " + parameter.name());
    }

    private static FindingFlowStep sinkStep(SinkMatch sink, int argumentIndex) {
        return new FindingFlowStep(
                FindingFlowStepKind.SINK,
                sink.call().call().arguments().get(argumentIndex).location(),
                sink.category() + " argument " + argumentIndex + " of "
                        + sink.call().call().methodName());
    }

    private static FindingSink findingSink(SinkMatch sink, int argumentIndex) {
        return new FindingSink(
                sink.ruleId(), sink.category(), sink.call().call().methodName(),
                argumentIndex, sink.location());
    }

    private static List<SameClassCallResolution> resolutionsFor(
            MethodInfo method, List<SameClassCallResolution> resolutions) {
        return resolutions.stream().filter(item -> item.caller().equals(method)).toList();
    }

    private static void mergeFinding(Map<FindingKey, Finding> findings, Finding incoming) {
        FindingKey key = new FindingKey(
                incoming.ruleId(), incoming.sink().location(), incoming.sink().argumentIndex());
        Finding current = findings.get(key);
        if (current == null) {
            findings.put(key, incoming);
            return;
        }
        LinkedHashMap<String, FindingSource> sources = new LinkedHashMap<>();
        current.sources().forEach(source -> sources.put(source.seedId(), source));
        incoming.sources().forEach(source -> sources.putIfAbsent(source.seedId(), source));
        LinkedHashSet<FindingFlow> flows = new LinkedHashSet<>(current.flows());
        flows.addAll(incoming.flows());
        findings.put(key, new Finding(
                current.ruleId(), current.vulnerabilityType(), current.cwe(), current.severity(),
                current.primaryLocation(), List.copyOf(sources.values()), current.sink(),
                List.copyOf(flows), current.evidence()));
    }

    private record MethodArtifacts(
            JavaFileInfo file,
            ClassInfo type,
            DataFlowResult dataFlow,
            CallSiteContextResolver calls) {}

    private record SyntheticSeeds(List<TaintSeed> seeds, Map<TaintSeed, Integer> indexes) {}

    private record RecursionResult(
            List<SameClassCallResolution> resolutions,
            Set<MethodInfo> recursiveMethods,
            List<UnsupportedInterproceduralFlow> unsupported) {}

    private record FindingKey(String ruleId, SourceLocation sinkLocation, int argumentIndex) {}

    private record ReturnExpression(Expression expression, SourceLocation location) {}
}
