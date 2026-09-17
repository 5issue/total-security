package com.totalsecurity.sast.interprocedural;

import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import com.totalsecurity.sast.rule.RuleRegistry;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Compatibility facade for STEP 18 using the shared project-local summary engine. */
public final class SameClassInterproceduralAnalysis {
    public SameClassInterproceduralResult analyze(
            JavaFileInfo file, ClassInfo type, RuleRegistry rules) {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(rules, "rules");
        JavaFileInfo restricted = new JavaFileInfo(
                file.packageName(), file.imports(), List.of(type), file.location());
        CrossClassInterproceduralResult project =
                new CrossClassInterproceduralAnalysis(false).analyze(List.of(restricted), rules);
        String owner = ProjectClassIndex.qualifiedName(restricted, type);

        LinkedHashMap<MethodInfo, SameClassMethodSummary> summaries = new LinkedHashMap<>();
        LinkedHashMap<MethodInfo, RuleAwareTaintResult> analyses = new LinkedHashMap<>();
        project.methodAnalyses().forEach((id, analysis) -> {
            if (id.ownerQualifiedName().equals(owner)) {
                analyses.put(id.method(), analysis);
            }
        });
        Set<String> declaredMethodNames = type.methods().stream()
                .map(MethodInfo::name)
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        List<SameClassCallResolution> resolutions = project.callResolutions().stream()
                .filter(resolution -> declaredMethodNames.contains(
                        resolution.call().call().methodName()))
                .map(resolution -> new SameClassCallResolution(
                        resolution.caller().method(),
                        resolution.call(),
                        resolution.status(),
                        resolution.target().map(ProjectMethodId::method),
                        resolution.unsupported().map(
                                SameClassInterproceduralAnalysis::sameClassUnsupported)))
                .toList();
        project.methodSummaries().forEach((id, summary) -> {
            if (id.ownerQualifiedName().equals(owner)) {
                List<UnsupportedInterproceduralFlow> methodUnsupported = resolutions.stream()
                        .filter(resolution -> resolution.caller().equals(id.method()))
                        .flatMap(resolution -> resolution.unsupported().stream())
                        .toList();
                summaries.put(id.method(), new SameClassMethodSummary(
                        summary.method(), summary.returnDependency(), summary.sinkDependencies(),
                        methodUnsupported));
            }
        });
        LinkedHashSet<UnsupportedInterproceduralFlow> unsupported = new LinkedHashSet<>();
        resolutions.stream().flatMap(resolution -> resolution.unsupported().stream())
                .forEach(unsupported::add);
        return new SameClassInterproceduralResult(
                Map.copyOf(summaries), Map.copyOf(analyses), resolutions,
                List.copyOf(unsupported), project.findings());
    }

    private static UnsupportedInterproceduralFlow sameClassUnsupported(
            UnsupportedInterproceduralFlow unsupported) {
        UnsupportedInterproceduralReason reason = switch (unsupported.reason()) {
            case UNKNOWN_RECEIVER_TYPE, EXTERNAL_CLASS, AMBIGUOUS_CLASS, INTERFACE_DISPATCH ->
                    UnsupportedInterproceduralReason.DYNAMIC_RECEIVER;
            default -> unsupported.reason();
        };
        return new UnsupportedInterproceduralFlow(
                reason, unsupported.detail(), unsupported.location());
    }
}
