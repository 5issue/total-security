package com.totalsecurity.sast.taint.model;

import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.rule.context.CallSiteContextResolver;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Resolves contextual method models without exposing Java/Spring names to taint analysis. */
public final class MethodTaintModelRegistry implements MethodTaintSemanticsProvider {
    private final CallSiteContextResolver contexts;
    private final List<MethodTaintModel> models;

    public MethodTaintModelRegistry(
            CallSiteContextResolver contexts, List<? extends MethodTaintModel> models) {
        this.contexts = Objects.requireNonNull(contexts, "contexts");
        this.models = List.copyOf(models);
    }

    @Override
    public Optional<MethodTaintSemantics> semanticsFor(MethodCallExpression call) {
        CallSiteContext context = contexts.resolve(call);
        List<ModelMatch> matches = new ArrayList<>();
        for (MethodTaintModel model : models) {
            Optional<MethodTaintSemantics> semantics = model.match(context);
            if (semantics.isPresent()) {
                matches.add(new ModelMatch(model, semantics.orElseThrow()));
            }
        }
        if (matches.isEmpty()) {
            return Optional.empty();
        }

        int highestRank = matches.stream()
                .mapToInt(match -> match.model().priority().rank())
                .max()
                .orElseThrow();
        List<ModelMatch> highest = matches.stream()
                .filter(match -> match.model().priority().rank() == highestRank)
                .toList();
        MethodTaintSemantics selected = highest.getFirst().semantics();
        if (highest.stream().anyMatch(match -> !match.semantics().equals(selected))) {
            throw new AmbiguousMethodTaintModelException(
                    call,
                    highest.getFirst().model().priority(),
                    highest.stream().map(match -> match.model().id()).sorted().toList());
        }
        return Optional.of(selected);
    }

    private record ModelMatch(MethodTaintModel model, MethodTaintSemantics semantics) {}
}
