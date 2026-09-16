package com.totalsecurity.sast.rule;

import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.rule.context.CallSiteContextResolver;
import com.totalsecurity.sast.rule.context.LightweightTypeContext;
import com.totalsecurity.sast.rule.context.ParameterContext;
import com.totalsecurity.sast.rule.sanitizer.SanitizerRule;
import com.totalsecurity.sast.rule.sink.JdbcConnectionSqlSinkRule;
import com.totalsecurity.sast.rule.sink.JdbcStatementSqlSinkRule;
import com.totalsecurity.sast.rule.sink.JdbcTemplateSqlSinkRule;
import com.totalsecurity.sast.rule.sink.JpaNativeQuerySinkRule;
import com.totalsecurity.sast.rule.sink.JavaRuntimeCommandSinkRule;
import com.totalsecurity.sast.rule.sink.JavaNioFilesPathSinkRule;
import com.totalsecurity.sast.rule.sink.SpringRestTemplateNetworkSinkRule;
import com.totalsecurity.sast.rule.sink.SinkMatch;
import com.totalsecurity.sast.rule.sink.SinkRule;
import com.totalsecurity.sast.rule.source.ServletRequestSourceRule;
import com.totalsecurity.sast.rule.source.SourceMatch;
import com.totalsecurity.sast.rule.source.SourceRule;
import com.totalsecurity.sast.rule.source.SpringMvcParameterSourceRule;
import com.totalsecurity.sast.taint.TaintSeed;
import com.totalsecurity.sast.taint.model.JavaStringMethodTaintModel;
import com.totalsecurity.sast.taint.model.JavaNioPathMethodTaintModel;
import com.totalsecurity.sast.taint.model.JavaUriMethodTaintModel;
import com.totalsecurity.sast.taint.model.MethodTaintModel;
import com.totalsecurity.sast.taint.model.MethodTaintModelRegistry;
import com.totalsecurity.sast.taint.model.MethodTaintSemanticsProvider;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Environment-extensible rules; matching is separate from vulnerability decisions. */
public final class RuleRegistry {
    private final List<SourceRule> sourceRules;
    private final List<SinkRule> sinkRules;
    private final List<SanitizerRule> sanitizerRules;
    private final List<MethodTaintModel> methodModels;

    public RuleRegistry(
            List<? extends SourceRule> sourceRules,
            List<? extends SinkRule> sinkRules,
            List<? extends SanitizerRule> sanitizerRules,
            List<? extends MethodTaintModel> methodModels) {
        this.sourceRules = List.copyOf(sourceRules);
        this.sinkRules = List.copyOf(sinkRules);
        this.sanitizerRules = List.copyOf(sanitizerRules);
        this.methodModels = List.copyOf(methodModels);
        validateIds(this.sourceRules.stream().map(SourceRule::id).toList(), "source");
        validateIds(this.sinkRules.stream().map(SinkRule::id).toList(), "sink");
        validateIds(this.sanitizerRules.stream().map(SanitizerRule::id).toList(), "sanitizer");
        validateIds(this.methodModels.stream().map(MethodTaintModel::id).toList(), "method model");
    }

    public static RuleRegistry javaSpringBackendDefaults() {
        List<SourceRule> sources = new ArrayList<>(SpringMvcParameterSourceRule.defaults());
        sources.add(new ServletRequestSourceRule());
        return new RuleRegistry(
                sources,
                List.of(
                        new JdbcStatementSqlSinkRule(),
                        new JdbcConnectionSqlSinkRule(),
                        new JdbcTemplateSqlSinkRule(),
                        new JpaNativeQuerySinkRule(),
                        new JavaRuntimeCommandSinkRule(),
                        new JavaNioFilesPathSinkRule(),
                        new SpringRestTemplateNetworkSinkRule()),
                List.of(),
                List.of(
                        new JavaStringMethodTaintModel(),
                        new JavaNioPathMethodTaintModel(),
                        new JavaUriMethodTaintModel()));
    }

    public List<SourceRule> sourceRules() {
        return sourceRules;
    }

    public List<SinkRule> sinkRules() {
        return sinkRules;
    }

    public List<SanitizerRule> sanitizerRules() {
        return sanitizerRules;
    }

    public List<MethodTaintModel> methodModels() {
        return methodModels;
    }

    public List<SourceMatch> matchSources(
            JavaFileInfo file, ClassInfo type, MethodInfo method, DataFlowResult dataFlow) {
        AnalysisInputs inputs = inputs(file, type, method, dataFlow);
        List<SourceMatch> matches = new ArrayList<>();
        for (var parameter : method.parameters()) {
            ParameterContext parameterContext =
                    new ParameterContext(file, type, method, parameter, inputs.types());
            for (SourceRule rule : sourceRules) {
                rule.match(parameterContext).ifPresent(matches::add);
            }
        }
        for (CallSiteContext call : inputs.calls().callSites()) {
            for (SourceRule rule : sourceRules) {
                rule.match(call).ifPresent(matches::add);
            }
        }
        return List.copyOf(matches);
    }

    public List<TaintSeed> sourceSeeds(
            JavaFileInfo file, ClassInfo type, MethodInfo method, DataFlowResult dataFlow) {
        return matchSources(file, type, method, dataFlow).stream()
                .map(match -> match.toTaintSeed(dataFlow))
                .toList();
    }

    public List<SinkMatch> matchSinks(
            JavaFileInfo file, ClassInfo type, MethodInfo method, DataFlowResult dataFlow) {
        AnalysisInputs inputs = inputs(file, type, method, dataFlow);
        List<SinkMatch> matches = new ArrayList<>();
        for (CallSiteContext call : inputs.calls().callSites()) {
            for (SinkRule rule : sinkRules) {
                rule.match(call).ifPresent(matches::add);
            }
        }
        return List.copyOf(matches);
    }

    public MethodTaintSemanticsProvider methodSemantics(
            JavaFileInfo file, ClassInfo type, MethodInfo method, DataFlowResult dataFlow) {
        AnalysisInputs inputs = inputs(file, type, method, dataFlow);
        List<MethodTaintModel> models = new ArrayList<>(sanitizerRules);
        models.addAll(methodModels);
        return new MethodTaintModelRegistry(inputs.calls(), models);
    }

    private static AnalysisInputs inputs(
            JavaFileInfo file, ClassInfo type, MethodInfo method, DataFlowResult dataFlow) {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(dataFlow, "dataFlow");
        LightweightTypeContext types = new LightweightTypeContext(file);
        return new AnalysisInputs(types, new CallSiteContextResolver(file, type, method, dataFlow));
    }

    private static void validateIds(List<String> ids, String kind) {
        if (ids.stream().anyMatch(id -> id == null || id.isBlank())) {
            throw new IllegalArgumentException(kind + " rule IDs must not be blank");
        }
        if (ids.stream().distinct().count() != ids.size()) {
            throw new IllegalArgumentException(kind + " rule IDs must be unique");
        }
    }

    private record AnalysisInputs(
            LightweightTypeContext types, CallSiteContextResolver calls) {}
}
