package com.totalsecurity.sast.taint;

import com.totalsecurity.sast.dataflow.Definition;
import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

public record DefinitionTaintSeed(String id, Definition definition) implements TaintSeed {
    public DefinitionTaintSeed {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(definition, "definition");
    }

    @Override
    public SourceLocation location() {
        return definition.location();
    }
}
