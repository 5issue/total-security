package com.totalsecurity.sast.detector.authn;

import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.Definition;
import com.totalsecurity.sast.dataflow.UseSite;
import com.totalsecurity.sast.finding.ChecklistFlowFinding;
import com.totalsecurity.sast.finding.FindingFlow;
import com.totalsecurity.sast.finding.FindingFlowStep;
import com.totalsecurity.sast.finding.FindingFlowStepKind;
import com.totalsecurity.sast.finding.FindingSeverity;
import com.totalsecurity.sast.finding.FindingSink;
import com.totalsecurity.sast.finding.FindingSource;
import com.totalsecurity.sast.finding.FindingSourceKind;
import com.totalsecurity.sast.interprocedural.CrossClassInterproceduralAnalysis;
import com.totalsecurity.sast.interprocedural.CrossClassInterproceduralResult;
import com.totalsecurity.sast.interprocedural.ProjectClassEntry;
import com.totalsecurity.sast.interprocedural.ProjectClassIndex;
import com.totalsecurity.sast.interprocedural.ProjectMethodId;
import com.totalsecurity.sast.ir.AssignmentInfo;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.MethodKind;
import com.totalsecurity.sast.ir.ParameterInfo;
import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.TypeKind;
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
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import com.totalsecurity.sast.rule.RuleRegistry;
import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.rule.context.CallSiteContextResolver;
import com.totalsecurity.sast.rule.context.LightweightTypeContext;
import com.totalsecurity.sast.rule.context.LombokGetterNamingContext;
import com.totalsecurity.sast.rule.sink.SinkCategory;
import com.totalsecurity.sast.rule.source.ExpressionSourceMatch;
import com.totalsecurity.sast.rule.source.ParameterSourceMatch;
import com.totalsecurity.sast.rule.source.SourceMatch;
import com.totalsecurity.sast.taint.TaintAnalysisResult;
import com.totalsecurity.sast.taint.TaintSeed;
import com.totalsecurity.sast.taint.TaintState;
import com.totalsecurity.sast.taint.TaintTrace;
import com.totalsecurity.sast.taint.TaintTraceEdge;
import com.totalsecurity.sast.taint.TaintTraceStep;
import com.totalsecurity.sast.taint.model.MethodTaintModel;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
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

/** AUTHN-11 policy analysis over existing project-local data-flow and taint summaries. */
public final class Authn11PlaintextRefreshTokenStorageDetector {
    public static final String RULE_ID = "AUTHN_11_PLAINTEXT_REFRESH_TOKEN_STORAGE";
    public static final String CHECKLIST_ID = "AUTHN-11";
    public static final String VULNERABILITY_TYPE = "Plaintext Refresh Token Storage";
    public static final String SINK_RULE_ID = "AUTHN_11_REFRESH_TOKEN_REPOSITORY_SAVE";
    public static final FindingSeverity SEVERITY = FindingSeverity.HIGH;

    private static final Set<String> SPRING_DATA_REPOSITORIES = Set.of(
            "org.springframework.data.repository.Repository",
            "org.springframework.data.repository.CrudRepository",
            "org.springframework.data.jpa.repository.JpaRepository");

    public Authn11AnalysisResult analyze(Collection<JavaFileInfo> files) {
        return analyze(files, LombokGetterNamingContext.unknown());
    }

    public Authn11AnalysisResult analyze(
            Collection<JavaFileInfo> files, LombokGetterNamingContext lombokNaming) {
        Objects.requireNonNull(files, "files");
        Objects.requireNonNull(lombokNaming, "lombokNaming");
        CrossClassInterproceduralResult project = new CrossClassInterproceduralAnalysis()
                .analyze(files, policyRules(files), lombokNaming);
        LinkedHashMap<FindingKey, ChecklistFlowFinding> findings = new LinkedHashMap<>();
        LinkedHashSet<UnsupportedAuthn11Flow> unsupported = new LinkedHashSet<>();

        for (Map.Entry<ProjectMethodId, RuleAwareTaintResult> item
                : project.methodAnalyses().entrySet()) {
            ProjectClassEntry owner = project.classIndex()
                    .uniqueClass(item.getKey().ownerQualifiedName()).orElse(null);
            if (owner == null) {
                continue;
            }
            inspectMethod(owner, item.getKey().method(), item.getValue(), project.classIndex(),
                    lombokNaming, findings, unsupported);
        }
        return new Authn11AnalysisResult(
                findings.values().stream()
                        .sorted(Comparator.comparing((ChecklistFlowFinding finding) ->
                                        finding.primaryLocation().file().toString())
                                .thenComparingInt(finding -> finding.primaryLocation().startLine())
                                .thenComparingInt(finding -> finding.primaryLocation().startColumn()))
                        .toList(),
                unsupported.stream()
                        .sorted(Comparator.comparing((UnsupportedAuthn11Flow item) ->
                                        item.location().file().toString())
                                .thenComparingInt(item -> item.location().startLine())
                                .thenComparing(UnsupportedAuthn11Flow::reason))
                        .toList());
    }

    private static RuleRegistry policyRules(Collection<JavaFileInfo> files) {
        RuleRegistry defaults = RuleRegistry.javaSpringBackendDefaults();
        List<MethodTaintModel> models = new ArrayList<>(defaults.methodModels());
        models.add(new RefreshTokenEncodingMethodTaintModel());
        return new RuleRegistry(
                List.of(new RefreshTokenSourceRule()),
                List.of(),
                List.of(new RefreshTokenHashSanitizerRule(
                        new CryptographicRefreshTokenHasherDiscovery().discover(files))),
                models);
    }

    private static void inspectMethod(
            ProjectClassEntry owner,
            MethodInfo method,
            RuleAwareTaintResult analysis,
            ProjectClassIndex index,
            LombokGetterNamingContext lombokNaming,
            Map<FindingKey, ChecklistFlowFinding> findings,
            Set<UnsupportedAuthn11Flow> unsupported) {
        DataFlowResult dataFlow = analysis.taintResult().dataFlow();
        CallSiteContextResolver calls = new CallSiteContextResolver(
                owner.file(), owner.type(), method, dataFlow, index, lombokNaming);
        for (CallSiteContext call : calls.callSites()) {
            Optional<PersistenceTarget> target = persistenceTarget(call, index);
            if (target.isEmpty()) {
                continue;
            }
            List<Expression> payloads = payloadExpressions(
                    call.arguments().getFirst(), target.orElseThrow().entity(), calls,
                    dataFlow, index, newIdentitySet());
            if (payloads.isEmpty()) {
                unsupported.add(new UnsupportedAuthn11Flow(
                        "Exact refresh-token persistence call has no supported constructor, record, "
                                + "builder, or reaching-definition payload shape",
                        call.location()));
                continue;
            }
            List<RawFlow> rawFlows = new ArrayList<>();
            for (Expression payload : payloads) {
                var value = analysis.taintResult().taintOf(payload);
                if (value.state() == TaintState.UNKNOWN) {
                    unsupported.add(new UnsupportedAuthn11Flow(
                            "Refresh-token persistence payload taint is UNKNOWN",
                            payload.location()));
                    continue;
                }
                if (value.state() != TaintState.TAINTED) {
                    continue;
                }
                for (TaintSeed origin : value.origins()) {
                    analysis.sourceMatch(origin).ifPresent(source ->
                            rawFlows.add(new RawFlow(payload, origin, source)));
                }
            }
            if (!rawFlows.isEmpty()) {
                ChecklistFlowFinding finding = finding(call, analysis, rawFlows);
                findings.putIfAbsent(new FindingKey(RULE_ID, call.location()), finding);
            }
        }
    }

    private static Optional<PersistenceTarget> persistenceTarget(
            CallSiteContext call, ProjectClassIndex index) {
        if (!call.receiverBoundToValue()
                || !call.methodName().equals("save")
                || call.argumentCount() != 1
                || call.receiverQualifiedType().isEmpty()) {
            return Optional.empty();
        }
        String repositoryName = call.receiverQualifiedType().orElseThrow();
        if (!Authn11Names.isRefreshTokenRepository(repositoryName)) {
            return Optional.empty();
        }
        Optional<ProjectClassEntry> repository = index.uniqueClass(repositoryName);
        if (repository.isEmpty() || !provenJpaRepository(repository.orElseThrow(), index)) {
            return Optional.empty();
        }
        List<MethodInfo> saveMethods = repository.orElseThrow().type().methods().stream()
                .filter(method -> method.kind() == MethodKind.METHOD)
                .filter(method -> method.name().equals("save"))
                .filter(method -> method.parameters().size() == 1)
                .toList();
        if (saveMethods.size() != 1) {
            return Optional.empty();
        }
        Optional<ProjectClassEntry> entity = saveEntity(
                repository.orElseThrow(), saveMethods.getFirst(), index);
        if (entity.isEmpty() || !isRefreshTokenEntity(entity.orElseThrow(), index)) {
            return Optional.empty();
        }
        return Optional.of(new PersistenceTarget(repository.orElseThrow(), entity.orElseThrow()));
    }

    private static boolean provenJpaRepository(
            ProjectClassEntry repository, ProjectClassIndex index) {
        List<ProjectClassEntry> persistentOwners = index.uniqueClasses().stream()
                .filter(candidate -> candidate.qualifiedName().equals(repository.qualifiedName())
                        || index.isDeclaredSubtypeOf(
                                candidate.qualifiedName(), repository.qualifiedName()))
                .filter(candidate -> directlyExtendsSpringDataRepository(candidate, index))
                .toList();
        return persistentOwners.size() == 1;
    }

    private static boolean directlyExtendsSpringDataRepository(
            ProjectClassEntry candidate, ProjectClassIndex index) {
        LightweightTypeContext types = new LightweightTypeContext(
                candidate.file(), index, candidate.type());
        return java.util.stream.Stream.concat(
                        candidate.type().extendsTypes().stream(),
                        candidate.type().implementsTypes().stream())
                .map(types::qualifyType)
                .flatMap(Optional::stream)
                .anyMatch(SPRING_DATA_REPOSITORIES::contains);
    }

    private static Optional<ProjectClassEntry> saveEntity(
            ProjectClassEntry repository, MethodInfo save, ProjectClassIndex index) {
        ParameterInfo parameter = save.parameters().getFirst();
        String declared = parameter.type();
        List<String> bounds = save.typeParameters().stream()
                .filter(type -> type.name().equals(declared))
                .flatMap(type -> type.upperBounds().stream())
                .toList();
        if (bounds.size() > 1) {
            return Optional.empty();
        }
        String entityType = bounds.size() == 1 ? bounds.getFirst() : declared;
        LightweightTypeContext types = new LightweightTypeContext(
                repository.file(), index, repository.type());
        return types.qualifyType(entityType).flatMap(index::uniqueClass);
    }

    private static boolean isRefreshTokenEntity(
            ProjectClassEntry entity, ProjectClassIndex index) {
        if (!Authn11Names.isRefreshTokenType(entity.qualifiedName())) {
            return false;
        }
        LightweightTypeContext types = new LightweightTypeContext(
                entity.file(), index, entity.type());
        return entity.type().annotations().stream().anyMatch(annotation ->
                types.annotationMatches(annotation.name(), "jakarta.persistence.Entity"));
    }

    private static List<Expression> payloadExpressions(
            Expression expression,
            ProjectClassEntry entity,
            CallSiteContextResolver calls,
            DataFlowResult dataFlow,
            ProjectClassIndex index,
            Set<Expression> visited) {
        if (!visited.add(expression)) {
            return List.of();
        }
        if (expression instanceof ParenthesizedExpression parenthesized) {
            return payloadExpressions(
                    parenthesized.expression(), entity, calls, dataFlow, index, visited);
        }
        if (expression instanceof AssignmentExpression assignment) {
            return payloadExpressions(
                    assignment.assignment().right(), entity, calls, dataFlow, index, visited);
        }
        if (expression instanceof VariableReference reference) {
            return dataFlow.reachingDefinitions(reference).stream()
                    .map(Definition::assignedExpression)
                    .flatMap(Optional::stream)
                    .flatMap(value -> payloadExpressions(
                            value, entity, calls, dataFlow, index, visited).stream())
                    .distinct()
                    .toList();
        }
        if (expression instanceof ObjectCreationExpression creation) {
            return constructorPayloads(creation, entity, calls, index);
        }
        if (expression instanceof MethodCallExpression call) {
            return builderPayloads(call, entity, calls, index);
        }
        return List.of();
    }

    private static List<Expression> constructorPayloads(
            ObjectCreationExpression creation,
            ProjectClassEntry entity,
            CallSiteContextResolver calls,
            ProjectClassIndex index) {
        if (calls.types().qualifyType(creation.typeName())
                .filter(entity.qualifiedName()::equals).isEmpty()) {
            return List.of();
        }
        List<String> tokenFields = tokenFields(entity, index);
        if (entity.type().kind() == TypeKind.RECORD
                && entity.type().recordComponents().size() == creation.arguments().size()) {
            List<Expression> result = new ArrayList<>();
            for (int componentIndex = 0;
                    componentIndex < entity.type().recordComponents().size();
                    componentIndex++) {
                var component = entity.type().recordComponents().get(componentIndex);
                if (tokenFields.contains(component.name())) {
                    result.add(creation.arguments().get(componentIndex));
                }
            }
            return List.copyOf(result);
        }
        List<MethodInfo> constructors = entity.type().methods().stream()
                .filter(method -> method.kind() == MethodKind.CONSTRUCTOR)
                .filter(method -> method.parameters().size() == creation.arguments().size())
                .toList();
        if (constructors.size() != 1) {
            return List.of();
        }
        Map<String, String> parameterFields = constructorParameterFields(constructors.getFirst());
        List<Expression> result = new ArrayList<>();
        for (int argumentIndex = 0;
                argumentIndex < constructors.getFirst().parameters().size();
                argumentIndex++) {
            ParameterInfo parameter = constructors.getFirst().parameters().get(argumentIndex);
            String field = parameterFields.get(parameter.name());
            if (field != null && tokenFields.contains(field)) {
                result.add(creation.arguments().get(argumentIndex));
            }
        }
        return List.copyOf(result);
    }

    private static List<Expression> builderPayloads(
            MethodCallExpression expression,
            ProjectClassEntry entity,
            CallSiteContextResolver calls,
            ProjectClassIndex index) {
        if (!expression.call().methodName().equals("build")
                || !expression.call().arguments().isEmpty()
                || expression.call().receiver().isEmpty()) {
            return List.of();
        }
        Set<String> fields = Set.copyOf(tokenFields(entity, index));
        Set<String> builderSetters = lombokBuilderSetters(entity, index).entrySet().stream()
                .filter(entry -> fields.contains(entry.getValue()))
                .map(Map.Entry::getKey)
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        if (builderSetters.isEmpty()) {
            return List.of();
        }
        List<Expression> payloads = new ArrayList<>();
        Expression cursor = expression.call().receiver().orElseThrow();
        while (cursor instanceof MethodCallExpression call) {
            if (call.call().methodName().equals("builder")
                    && call.call().arguments().isEmpty()
                    && calls.resolve(call).receiverQualifiedType()
                            .filter(entity.qualifiedName()::equals).isPresent()) {
                return List.copyOf(payloads);
            }
            if (call.call().arguments().size() == 1
                    && builderSetters.contains(call.call().methodName())) {
                payloads.add(call.call().arguments().getFirst());
            }
            if (call.call().receiver().isEmpty()) {
                return List.of();
            }
            cursor = call.call().receiver().orElseThrow();
        }
        return List.of();
    }

    private static List<String> tokenFields(
            ProjectClassEntry entity, ProjectClassIndex index) {
        LightweightTypeContext types = new LightweightTypeContext(
                entity.file(), index, entity.type());
        List<String> names = new ArrayList<>();
        entity.type().fields().stream()
                .filter(field -> Authn11Names.isTokenStorageName(field.name()))
                .filter(field -> !field.staticMember() && !field.transientMember())
                .filter(field -> field.annotations().stream().noneMatch(annotation ->
                        types.annotationMatches(
                                annotation.name(), "jakarta.persistence.Transient")))
                .filter(field -> types.qualifyTypeShape(field.type())
                        .filter("java.lang.String"::equals).isPresent())
                .map(field -> field.name())
                .forEach(names::add);
        entity.type().recordComponents().stream()
                .filter(component -> Authn11Names.isTokenStorageName(component.name()))
                .filter(component -> component.annotations().stream().noneMatch(annotation ->
                        types.annotationMatches(
                                annotation.name(), "jakarta.persistence.Transient")))
                .filter(component -> types.qualifyTypeShape(component.declaredType())
                        .filter("java.lang.String"::equals).isPresent())
                .map(component -> component.name())
                .forEach(names::add);
        return List.copyOf(new LinkedHashSet<>(names));
    }

    private static Map<String, String> lombokBuilderSetters(
            ProjectClassEntry entity, ProjectClassIndex index) {
        LightweightTypeContext types = new LightweightTypeContext(
                entity.file(), index, entity.type());
        List<MethodInfo> builders = entity.type().methods().stream()
                .filter(method -> method.kind() == MethodKind.CONSTRUCTOR)
                .filter(method -> method.annotations().stream().anyMatch(annotation ->
                        annotation.arguments().isEmpty()
                                && types.annotationMatches(annotation.name(), "lombok.Builder")))
                .toList();
        return builders.size() == 1
                ? constructorParameterFields(builders.getFirst())
                : Map.of();
    }

    /** Maps a constructor parameter to the exact instance field it assigns exactly once. */
    private static Map<String, String> constructorParameterFields(MethodInfo constructor) {
        Map<String, List<AssignmentInfo>> byField = new LinkedHashMap<>();
        for (AssignmentInfo assignment : constructor.assignments()) {
            exactThisField(assignment.left()).ifPresent(field ->
                    byField.computeIfAbsent(field, ignored -> new ArrayList<>()).add(assignment));
        }
        Set<String> parameters = constructor.parameters().stream()
                .map(ParameterInfo::name)
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        LinkedHashMap<String, String> result = new LinkedHashMap<>();
        byField.forEach((field, assignments) -> {
            if (assignments.size() != 1 || !assignments.getFirst().operator().equals("=")) {
                return;
            }
            exactVariable(assignments.getFirst().right())
                    .filter(parameters::contains)
                    .ifPresent(parameter -> result.put(parameter, field));
        });
        return Map.copyOf(result);
    }

    private static Optional<String> exactThisField(Expression expression) {
        if (expression instanceof ParenthesizedExpression parenthesized) {
            return exactThisField(parenthesized.expression());
        }
        if (expression instanceof FieldAccessExpression field
                && field.target() instanceof VariableReference target
                && target.name().equals("this")) {
            return Optional.of(field.fieldName());
        }
        return Optional.empty();
    }

    private static Optional<String> exactVariable(Expression expression) {
        if (expression instanceof ParenthesizedExpression parenthesized) {
            return exactVariable(parenthesized.expression());
        }
        return expression instanceof VariableReference reference
                ? Optional.of(reference.name())
                : Optional.empty();
    }

    private static ChecklistFlowFinding finding(
            CallSiteContext sink,
            RuleAwareTaintResult analysis,
            List<RawFlow> rawFlows) {
        LinkedHashMap<String, FindingSource> sources = new LinkedHashMap<>();
        LinkedHashSet<FindingFlow> flows = new LinkedHashSet<>();
        for (RawFlow raw : rawFlows) {
            FindingSource source = source(raw.source(), raw.seed());
            sources.putIfAbsent(source.seedId(), source);
            List<FindingFlowStep> steps = new ArrayList<>(flowTo(
                    analysis.taintResult(), raw.payload(), raw.seed(), source));
            steps.add(new FindingFlowStep(
                    FindingFlowStepKind.SINK,
                    sink.location(),
                    "Raw refresh-token payload reaches exact repository save argument 0"));
            flows.add(new FindingFlow(source, steps));
        }
        FindingSink findingSink = new FindingSink(
                SINK_RULE_ID,
                SinkCategory.REFRESH_TOKEN_PERSISTENCE,
                sink.methodName(),
                0,
                sink.location());
        return new ChecklistFlowFinding(
                RULE_ID,
                CHECKLIST_ID,
                VULNERABILITY_TYPE,
                SEVERITY,
                sink.location(),
                List.copyOf(sources.values()),
                findingSink,
                List.copyOf(flows),
                CHECKLIST_ID + ": source-proven raw refresh token reaches exact DB persistence "
                        + "without a supported hash output (token value redacted)");
    }

    private static FindingSource source(SourceMatch match, TaintSeed seed) {
        return switch (match) {
            case ParameterSourceMatch parameter -> new FindingSource(
                    parameter.ruleId(), seed.id(), FindingSourceKind.PARAMETER,
                    parameter.location(), "Raw refresh-token parameter "
                            + parameter.parameter().name(), parameter.evidence());
            case ExpressionSourceMatch expression -> new FindingSource(
                    expression.ruleId(), seed.id(), FindingSourceKind.EXPRESSION,
                    expression.location(), "Refresh-token issuance result",
                    expression.evidence());
        };
    }

    private static List<FindingFlowStep> flowTo(
            TaintAnalysisResult taint,
            Expression endpoint,
            TaintSeed seed,
            FindingSource source) {
        TaintTrace trace = taint.traceTo(endpoint);
        TaintTraceStep sourceStep = trace.steps().stream()
                .filter(step -> step.seed().filter(seed::equals).isPresent())
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "AUTHN-11 trace lacks source origin " + seed.id()));
        List<FindingFlowStep> result = new ArrayList<>();
        for (TaintTraceStep step : shortestPath(trace, sourceStep)) {
            result.add(toFlowStep(step, source));
        }
        return List.copyOf(result);
    }

    private static List<TaintTraceStep> shortestPath(
            TaintTrace trace, TaintTraceStep source) {
        Map<TaintTraceStep, List<TaintTraceStep>> outgoing = new HashMap<>();
        for (TaintTraceEdge edge : trace.edges()) {
            outgoing.computeIfAbsent(edge.source(), ignored -> new ArrayList<>())
                    .add(edge.target());
        }
        outgoing.values().forEach(values -> values.sort(Comparator.comparingInt(TaintTraceStep::id)));
        ArrayDeque<TaintTraceStep> work = new ArrayDeque<>();
        Set<TaintTraceStep> visited = new LinkedHashSet<>();
        Map<TaintTraceStep, TaintTraceStep> predecessor = new HashMap<>();
        work.add(source);
        visited.add(source);
        while (!work.isEmpty()) {
            TaintTraceStep current = work.removeFirst();
            if (current.equals(trace.target())) {
                ArrayList<TaintTraceStep> reversed = new ArrayList<>();
                reversed.add(current);
                while (!current.equals(source)) {
                    current = Objects.requireNonNull(predecessor.get(current));
                    reversed.add(current);
                }
                java.util.Collections.reverse(reversed);
                return reversed;
            }
            for (TaintTraceStep next : outgoing.getOrDefault(current, List.of())) {
                if (visited.add(next)) {
                    predecessor.put(next, current);
                    work.addLast(next);
                }
            }
        }
        throw new IllegalStateException("No AUTHN-11 provenance path to persistence payload");
    }

    private static FindingFlowStep toFlowStep(
            TaintTraceStep step, FindingSource source) {
        return switch (step.kind()) {
            case SEED -> new FindingFlowStep(
                    FindingFlowStepKind.SOURCE, source.location(), source.summary());
            case DEFINITION -> new FindingFlowStep(
                    FindingFlowStepKind.DEFINITION,
                    step.definition().orElseThrow().location(),
                    "Definition of " + step.definition().orElseThrow().variable().name());
            case USE -> new FindingFlowStep(
                    FindingFlowStepKind.USE,
                    step.useSite().orElseThrow().reference().location(),
                    "Use of " + step.useSite().orElseThrow().variable().name());
            case EXPRESSION -> new FindingFlowStep(
                    FindingFlowStepKind.EXPRESSION,
                    step.expression().orElseThrow().location(),
                    expressionSummary(step.expression().orElseThrow()));
        };
    }

    private static String expressionSummary(Expression expression) {
        return switch (expression) {
            case VariableReference reference -> "Variable reference " + reference.name();
            case Literal literal -> "Literal " + literal.kind();
            case BinaryExpression binary -> "Binary expression " + binary.operator();
            case AssignmentExpression assignment ->
                    "Assignment expression " + assignment.assignment().operator();
            case MethodCallExpression call -> "Return value of " + call.call().methodName();
            case ObjectCreationExpression creation -> "Object creation " + creation.typeName();
            case FieldAccessExpression field -> "Field access " + field.fieldName();
            case ParenthesizedExpression ignored -> "Parenthesized expression";
            case UnknownExpression unknown -> "Unsupported expression " + unknown.syntaxKind();
        };
    }

    private static Set<Expression> newIdentitySet() {
        return java.util.Collections.newSetFromMap(new IdentityHashMap<>());
    }

    private record PersistenceTarget(ProjectClassEntry repository, ProjectClassEntry entity) {}

    private record RawFlow(Expression payload, TaintSeed seed, SourceMatch source) {}

    private record FindingKey(String ruleId, SourceLocation location) {}
}
