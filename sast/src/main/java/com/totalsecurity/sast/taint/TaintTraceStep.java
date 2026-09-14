package com.totalsecurity.sast.taint;

import com.totalsecurity.sast.dataflow.Definition;
import com.totalsecurity.sast.dataflow.UseSite;
import com.totalsecurity.sast.ir.expression.Expression;
import java.util.Objects;
import java.util.Optional;

/** A stable static node in the provenance graph. */
public record TaintTraceStep(
        int id,
        TaintTraceStepKind kind,
        Optional<TaintSeed> seed,
        Optional<Definition> definition,
        Optional<UseSite> useSite,
        Optional<Expression> expression) {
    public TaintTraceStep {
        if (id < 0) {
            throw new IllegalArgumentException("Trace step id must be non-negative");
        }
        Objects.requireNonNull(kind, "kind");
        seed = Objects.requireNonNull(seed, "seed");
        definition = Objects.requireNonNull(definition, "definition");
        useSite = Objects.requireNonNull(useSite, "useSite");
        expression = Objects.requireNonNull(expression, "expression");
        int present = (seed.isPresent() ? 1 : 0)
                + (definition.isPresent() ? 1 : 0)
                + (useSite.isPresent() ? 1 : 0)
                + (expression.isPresent() ? 1 : 0);
        if (present != 1) {
            throw new IllegalArgumentException("A trace step must describe exactly one static occurrence");
        }
    }
}
