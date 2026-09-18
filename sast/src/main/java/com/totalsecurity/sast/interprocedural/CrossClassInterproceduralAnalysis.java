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
import java.util.Collection;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Project-local orchestration for exact, acyclic, directly typed method calls. */
public final class CrossClassInterproceduralAnalysis {
    private final IntraproceduralTaintAnalysis taintAnalysis = new IntraproceduralTaintAnalysis();
    private final boolean qualifyBoundaryOwners;

    public CrossClassInterproceduralAnalysis() {
        this(true);
    }

    CrossClassInterproceduralAnalysis(boolean qualifyBoundaryOwners) {
        this.qualifyBoundaryOwners = qualifyBoundaryOwners;
    }

    public CrossClassInterproceduralResult analyze(
            Collection<JavaFileInfo> files, RuleRegistry rules) {
        Objects.requireNonNull(files, "files");
        Objects.requireNonNull(rules, "rules");
        ProjectClassIndex index = new ProjectClassIndex(files);
        LinkedHashSet<UnsupportedInterproceduralFlow> unsupported = duplicateClassProblems(index);
        LinkedHashMap<ProjectMethodId, MethodArtifacts> artifacts = prepare(index);
        CrossClassCallResolver resolver = new CrossClassCallResolver(index);
        List<ProjectCallResolution> initial = resolveCalls(artifacts, resolver);
        RecursionResult recursion = excludeRecursion(initial);
        List<ProjectCallResolution> resolutions = recursion.resolutions();
        unsupported.addAll(recursion.unsupported());
        resolutions.stream().flatMap(item -> item.unsupported().stream()).forEach(unsupported::add);

        LinkedHashMap<ProjectMethodId, SameClassMethodSummary> summaries = new LinkedHashMap<>();
        for (ProjectMethodId method : artifacts.keySet()) {
            summarize(method, artifacts, resolutions, recursion.recursiveMethods(), summaries, rules);
        }
        summaries.values().forEach(summary -> unsupported.addAll(summary.unsupported()));

        LinkedHashMap<ProjectMethodId, RuleAwareTaintResult> actual = new LinkedHashMap<>();
        for (Map.Entry<ProjectMethodId, MethodArtifacts> entry : artifacts.entrySet()) {
            ProjectMethodId method = entry.getKey();
            MethodArtifacts methodArtifacts = entry.getValue();
            MethodTaintSemanticsProvider semantics = semantics(
                    method, methodArtifacts, resolutions, summaries, rules);
            List<SourceMatch> sources = rules.matchSources(
                    methodArtifacts.owner().file(), methodArtifacts.owner().type(),
                    method.method(), methodArtifacts.dataFlow());
            List<TaintSeed> seeds = sources.stream()
                    .map(source -> source.toTaintSeed(methodArtifacts.dataFlow()))
                    .toList();
            TaintAnalysisResult taint = taintAnalysis.analyze(
                    methodArtifacts.dataFlow(), seeds, semantics);
            List<SinkMatch> sinks = rules.matchSinks(
                    methodArtifacts.owner().file(), methodArtifacts.owner().type(),
                    method.method(), methodArtifacts.dataFlow());
            actual.put(method, new RuleAwareTaintResult(sources, seeds, taint, sinks));
        }

        LinkedHashMap<FindingKey, Finding> findings = new LinkedHashMap<>();
        for (Map.Entry<ProjectMethodId, RuleAwareTaintResult> entry : actual.entrySet()) {
            for (Finding finding : localFindings(entry.getValue())) {
                mergeFinding(findings, augmentReturnBoundaries(
                        finding, entry.getKey(), entry.getValue(), resolutions, summaries));
            }
        }
        addCrossMethodFindings(findings, actual, resolutions, summaries);

        return new CrossClassInterproceduralResult(
                index, summaries, actual, resolutions, List.copyOf(unsupported),
                findings.values().stream()
                        .sorted(Comparator.comparing(
                                        (Finding finding) -> finding.sink().location().file().toString())
                                .thenComparingInt(finding -> finding.sink().location().startLine()))
                        .toList());
    }

    private static LinkedHashSet<UnsupportedInterproceduralFlow> duplicateClassProblems(
            ProjectClassIndex index) {
        LinkedHashSet<UnsupportedInterproceduralFlow> result = new LinkedHashSet<>();
        for (String fqn : index.ambiguousQualifiedNames()) {
            for (ProjectClassEntry entry : index.ambiguousEntries(fqn)) {
                result.add(new UnsupportedInterproceduralFlow(
                        UnsupportedInterproceduralReason.AMBIGUOUS_CLASS,
                        "Duplicate project class FQN " + fqn,
                        entry.type().location()));
            }
        }
        return result;
    }

    private static LinkedHashMap<ProjectMethodId, MethodArtifacts> prepare(ProjectClassIndex index) {
        LinkedHashMap<ProjectMethodId, MethodArtifacts> result = new LinkedHashMap<>();
        for (ProjectClassEntry owner : index.uniqueClasses()) {
            for (MethodInfo method : owner.type().methods()) {
                if (method.body().isEmpty()) {
                    continue;
                }
                ProjectMethodId id = new ProjectMethodId(owner.qualifiedName(), method);
                ControlFlowGraph graph = new ControlFlowGraphBuilder().build(method);
                DataFlowResult dataFlow = new ReachingDefinitionsAnalysis().analyze(graph);
                result.put(id, new MethodArtifacts(
                        owner, dataFlow,
                        new CallSiteContextResolver(
                                owner.file(), owner.type(), method, dataFlow, index::contains)));
            }
        }
        return result;
    }

    private static List<ProjectCallResolution> resolveCalls(
            Map<ProjectMethodId, MethodArtifacts> artifacts,
            CrossClassCallResolver resolver) {
        List<ProjectCallResolution> result = new ArrayList<>();
        artifacts.forEach((method, methodArtifacts) -> methodArtifacts.calls().callSites().forEach(call ->
                result.add(resolver.resolve(
                        method, methodArtifacts.owner(), call.call(), methodArtifacts.calls()))));
        return List.copyOf(result);
    }

    private static RecursionResult excludeRecursion(List<ProjectCallResolution> resolutions) {
        Map<ProjectMethodId, Set<ProjectMethodId>> adjacency = new LinkedHashMap<>();
        for (ProjectCallResolution resolution : resolutions) {
            resolution.target().ifPresent(target -> adjacency
                    .computeIfAbsent(resolution.caller(), ignored -> new LinkedHashSet<>())
                    .add(target));
        }
        Set<MethodCallExpression> recursiveCalls = java.util.Collections.newSetFromMap(
                new IdentityHashMap<>());
        LinkedHashSet<ProjectMethodId> recursiveMethods = new LinkedHashSet<>();
        for (ProjectCallResolution resolution : resolutions) {
            if (resolution.target().isEmpty()) {
                continue;
            }
            ProjectMethodId target = resolution.target().orElseThrow();
            if (target.equals(resolution.caller())
                    || reachable(target, resolution.caller(), adjacency, new LinkedHashSet<>())) {
                recursiveCalls.add(resolution.call());
                recursiveMethods.add(resolution.caller());
                recursiveMethods.add(target);
            }
        }
        List<UnsupportedInterproceduralFlow> unsupported = new ArrayList<>();
        List<ProjectCallResolution> replaced = new ArrayList<>();
        for (ProjectCallResolution resolution : resolutions) {
            if (!recursiveCalls.contains(resolution.call())) {
                replaced.add(resolution);
                continue;
            }
            UnsupportedInterproceduralFlow item = new UnsupportedInterproceduralFlow(
                    UnsupportedInterproceduralReason.RECURSIVE_CALL,
                    "Recursive project-local edge is excluded from summary expansion",
                    resolution.call().location());
            unsupported.add(item);
            replaced.add(new ProjectCallResolution(
                    resolution.caller(), resolution.call(), SameClassCallStatus.UNSUPPORTED,
                    Optional.empty(), Optional.of(item)));
        }
        return new RecursionResult(
                List.copyOf(replaced), Set.copyOf(recursiveMethods), List.copyOf(unsupported));
    }

    private static boolean reachable(
            ProjectMethodId current,
            ProjectMethodId target,
            Map<ProjectMethodId, Set<ProjectMethodId>> adjacency,
            Set<ProjectMethodId> visited) {
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
            ProjectMethodId method,
            Map<ProjectMethodId, MethodArtifacts> artifacts,
            List<ProjectCallResolution> resolutions,
            Set<ProjectMethodId> recursiveMethods,
            Map<ProjectMethodId, SameClassMethodSummary> completed,
            RuleRegistry rules) {
        SameClassMethodSummary existing = completed.get(method);
        if (existing != null) {
            return existing;
        }
        MethodArtifacts methodArtifacts = artifacts.get(method);
        if (methodArtifacts == null) {
            UnsupportedInterproceduralFlow noBody = new UnsupportedInterproceduralFlow(
                    UnsupportedInterproceduralReason.NO_ANALYZABLE_BODY,
                    "Project-local target " + method.displayName()
                            + " has no analyzable method body",
                    method.method().location());
            SameClassMethodSummary summary = new SameClassMethodSummary(
                    method.method(), MethodReturnDependency.unknown(), List.of(), List.of(noBody));
            completed.put(method, summary);
            return summary;
        }
        if (recursiveMethods.contains(method)) {
            SameClassMethodSummary summary = new SameClassMethodSummary(
                    method.method(), MethodReturnDependency.unknown(), List.of(),
                    resolutionsFor(method, resolutions).stream()
                            .flatMap(item -> item.unsupported().stream()).toList());
            completed.put(method, summary);
            return summary;
        }
        for (ProjectCallResolution resolution : resolutionsFor(method, resolutions)) {
            resolution.target().ifPresent(target -> summarize(
                    target, artifacts, resolutions, recursiveMethods, completed, rules));
        }
        SyntheticSeeds synthetic = syntheticSeeds(method, methodArtifacts.dataFlow());
        MethodTaintSemanticsProvider semantics = semantics(
                method, methodArtifacts, resolutions, completed, rules);
        TaintAnalysisResult taint = taintAnalysis.analyze(
                methodArtifacts.dataFlow(), synthetic.seeds(), semantics);
        List<SinkMatch> sinks = rules.matchSinks(
                methodArtifacts.owner().file(), methodArtifacts.owner().type(),
                method.method(), methodArtifacts.dataFlow());
        List<InterproceduralSinkDependency> dependencies = new ArrayList<>();
        addDirectSinkDependencies(dependencies, sinks, taint, synthetic);
        addTransitiveSinkDependencies(
                dependencies, method, resolutions, completed, taint, synthetic);
        SameClassMethodSummary summary = new SameClassMethodSummary(
                method.method(),
                returnDependency(method, taint, synthetic, resolutions, completed),
                dependencies,
                resolutionsFor(method, resolutions).stream()
                        .flatMap(item -> item.unsupported().stream()).toList());
        completed.put(method, summary);
        return summary;
    }

    private static MethodTaintSemanticsProvider semantics(
            ProjectMethodId method,
            MethodArtifacts artifacts,
            List<ProjectCallResolution> resolutions,
            Map<ProjectMethodId, SameClassMethodSummary> summaries,
            RuleRegistry rules) {
        Map<MethodCallExpression, SameClassMethodSummary> callSummaries = new IdentityHashMap<>();
        for (ProjectCallResolution resolution : resolutionsFor(method, resolutions)) {
            resolution.target().map(summaries::get).ifPresent(summary ->
                    callSummaries.put(resolution.call(), summary));
        }
        List<MethodTaintModel> models = new ArrayList<>(rules.sanitizerRules());
        models.add(new ProjectMethodTaintModel(callSummaries));
        models.addAll(rules.methodModels());
        return new MethodTaintModelRegistry(artifacts.calls(), models);
    }

    private static SyntheticSeeds syntheticSeeds(
            ProjectMethodId method, DataFlowResult dataFlow) {
        List<TaintSeed> seeds = new ArrayList<>();
        Map<TaintSeed, Integer> indexes = new LinkedHashMap<>();
        for (int index = 0; index < method.method().parameters().size(); index++) {
            ParameterInfo parameter = method.method().parameters().get(index);
            Definition definition = dataFlow.definitions().stream()
                    .filter(candidate -> candidate.kind() == DefinitionKind.PARAMETER)
                    .filter(candidate -> candidate.location().equals(parameter.location()))
                    .findFirst().orElseThrow();
            TaintSeed seed = new DefinitionTaintSeed(
                    "PROJECT_PARAMETER_" + index + "@" + method.displayName()
                            + ":" + parameter.location().startLine(),
                    definition);
            seeds.add(seed);
            indexes.put(seed, index);
        }
        return new SyntheticSeeds(List.copyOf(seeds), Map.copyOf(indexes));
    }

    private MethodReturnDependency returnDependency(
            ProjectMethodId method,
            TaintAnalysisResult taint,
            SyntheticSeeds synthetic,
            List<ProjectCallResolution> resolutions,
            Map<ProjectMethodId, SameClassMethodSummary> summaries) {
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
                        method, taint, origin,
                        InterproceduralFlowSupport.syntheticFlowTo(taint, expression, origin),
                        resolutions, summaries));
                path.add(returnStep(method, returned.location()));
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

    private void addTransitiveSinkDependencies(
            List<InterproceduralSinkDependency> output,
            ProjectMethodId method,
            List<ProjectCallResolution> resolutions,
            Map<ProjectMethodId, SameClassMethodSummary> summaries,
            TaintAnalysisResult taint,
            SyntheticSeeds synthetic) {
        for (ProjectCallResolution resolution : resolutionsFor(method, resolutions)) {
            if (resolution.target().isEmpty()) {
                continue;
            }
            ProjectMethodId target = resolution.target().orElseThrow();
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
                            method.method(), target.method(), resolution.call().location(),
                            nested.parameterIndexes()));
                    chain.addAll(nested.callChain());
                    output.add(new InterproceduralSinkDependency(
                            nested.sink(), nested.argumentIndex(), callerIndexes, flows, chain));
                }
            }
        }
    }

    private void addCrossMethodFindings(
            Map<FindingKey, Finding> findings,
            Map<ProjectMethodId, RuleAwareTaintResult> actual,
            List<ProjectCallResolution> resolutions,
            Map<ProjectMethodId, SameClassMethodSummary> summaries) {
        for (ProjectCallResolution resolution : resolutions) {
            if (resolution.target().isEmpty()) {
                continue;
            }
            RuleAwareTaintResult callerAnalysis = actual.get(resolution.caller());
            ProjectMethodId targetId = resolution.target().orElseThrow();
            SameClassMethodSummary target = summaries.get(targetId);
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
                                resolution.caller(), targetId, resolution.call().location()));
                        steps.add(bindingStep(targetId, parameterIndex));
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
                                "Tainted external input crosses a directly resolved project-local "
                                        + "call and reaches a supported " + spec.category() + " sink.");
                        mergeFinding(findings, finding);
                    }
                }
            }
        }
    }

    private Finding augmentReturnBoundaries(
            Finding finding,
            ProjectMethodId method,
            RuleAwareTaintResult actual,
            List<ProjectCallResolution> resolutions,
            Map<ProjectMethodId, SameClassMethodSummary> summaries) {
        List<ProjectCallResolution> calls = resolutionsFor(method, resolutions).stream()
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
                    method, actual.taintResult(), origin, flow.steps(), calls, summaries);
            augmented.add(new FindingFlow(flow.source(), steps));
        }
        return new Finding(
                finding.ruleId(), finding.vulnerabilityType(), finding.cwe(), finding.severity(),
                finding.primaryLocation(), finding.sources(), finding.sink(), augmented,
                finding.evidence());
    }

    private List<FindingFlowStep> expandReturnBoundaries(
            ProjectMethodId method,
            TaintAnalysisResult taint,
            TaintSeed origin,
            List<FindingFlowStep> original,
            List<ProjectCallResolution> resolutions,
            Map<ProjectMethodId, SameClassMethodSummary> summaries) {
        List<ProjectCallResolution> calls = resolutionsFor(method, resolutions).stream()
                .filter(item -> item.target().isPresent()).toList();
        if (calls.isEmpty()) {
            return List.copyOf(original);
        }
        List<FindingFlowStep> expanded = new ArrayList<>();
        for (FindingFlowStep step : original) {
            ProjectCallResolution boundary = calls.stream()
                    .filter(item -> item.call().location().equals(step.location()))
                    .findFirst().orElse(null);
            if (boundary != null && step.kind() == FindingFlowStepKind.EXPRESSION) {
                ProjectMethodId target = boundary.target().orElseThrow();
                SameClassMethodSummary summary = summaries.get(target);
                if (summary != null) {
                    int parameterIndex = matchingParameterIndex(
                            taint, boundary.call(), origin,
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
                .filter(index -> taint.argumentTaint(call, index).origins().contains(origin))
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

    private FindingFlowStep callStep(
            ProjectMethodId caller, ProjectMethodId callee, SourceLocation location) {
        String summary = qualifyBoundaryOwners || !caller.ownerQualifiedName()
                .equals(callee.ownerQualifiedName())
                ? "Project call " + caller.boundaryName() + " -> " + callee.boundaryName()
                : "Same-class call " + caller.method().name() + " -> " + callee.method().name();
        return new FindingFlowStep(FindingFlowStepKind.METHOD_CALL, location, summary);
    }

    private FindingFlowStep bindingStep(ProjectMethodId callee, int parameterIndex) {
        ParameterInfo parameter = callee.method().parameters().get(parameterIndex);
        String target = qualifyBoundaryOwners
                ? callee.boundaryName()
                : callee.method().name();
        return new FindingFlowStep(
                FindingFlowStepKind.PARAMETER_BINDING, parameter.location(),
                "Bind argument " + parameterIndex + " to " + target
                        + " parameter " + parameter.name());
    }

    private FindingFlowStep returnStep(ProjectMethodId method, SourceLocation location) {
        String target = qualifyBoundaryOwners ? method.boundaryName() : method.method().name();
        return new FindingFlowStep(
                FindingFlowStepKind.METHOD_RETURN, location, "Return from " + target);
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

    private static List<ProjectCallResolution> resolutionsFor(
            ProjectMethodId method, List<ProjectCallResolution> resolutions) {
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
            ProjectClassEntry owner,
            DataFlowResult dataFlow,
            CallSiteContextResolver calls) {}

    private record SyntheticSeeds(List<TaintSeed> seeds, Map<TaintSeed, Integer> indexes) {}

    private record RecursionResult(
            List<ProjectCallResolution> resolutions,
            Set<ProjectMethodId> recursiveMethods,
            List<UnsupportedInterproceduralFlow> unsupported) {}

    private record FindingKey(String ruleId, SourceLocation sinkLocation, int argumentIndex) {}

    private record ReturnExpression(Expression expression, SourceLocation location) {}
}
