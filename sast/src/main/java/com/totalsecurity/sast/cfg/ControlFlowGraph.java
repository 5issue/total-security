package com.totalsecurity.sast.cfg;

import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.statement.Statement;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Immutable method-level control-flow graph. */
public final class ControlFlowGraph {
    private final MethodInfo method;
    private final BasicBlock entry;
    private final BasicBlock exit;
    private final List<BasicBlock> blocks;
    private final List<CfgEdge> edges;
    private final List<UnsupportedControlFlow> unsupportedControlFlow;

    public ControlFlowGraph(
            MethodInfo method,
            BasicBlock entry,
            BasicBlock exit,
            List<BasicBlock> blocks,
            List<CfgEdge> edges,
            List<UnsupportedControlFlow> unsupportedControlFlow) {
        this.method = Objects.requireNonNull(method, "method");
        this.entry = Objects.requireNonNull(entry, "entry");
        this.exit = Objects.requireNonNull(exit, "exit");
        this.blocks = List.copyOf(blocks);
        this.edges = List.copyOf(edges);
        this.unsupportedControlFlow = List.copyOf(unsupportedControlFlow);

        Set<Integer> ids = new LinkedHashSet<>();
        for (BasicBlock block : this.blocks) {
            if (!ids.add(block.id())) {
                throw new IllegalArgumentException("Duplicate basic block id: " + block.id());
            }
        }
        if (!this.blocks.contains(entry) || !this.blocks.contains(exit)) {
            throw new IllegalArgumentException("Entry and exit must belong to the graph");
        }
        for (CfgEdge edge : this.edges) {
            if (!this.blocks.contains(edge.source()) || !this.blocks.contains(edge.target())) {
                throw new IllegalArgumentException("Edge endpoint does not belong to the graph");
            }
        }
    }

    public MethodInfo method() {
        return method;
    }

    public BasicBlock entry() {
        return entry;
    }

    public BasicBlock exit() {
        return exit;
    }

    public List<BasicBlock> blocks() {
        return blocks;
    }

    public List<CfgEdge> edges() {
        return edges;
    }

    public List<UnsupportedControlFlow> unsupportedControlFlow() {
        return unsupportedControlFlow;
    }

    public List<CfgEdge> outgoingEdges(BasicBlock block) {
        requireBlock(block);
        return edges.stream().filter(edge -> edge.source().equals(block)).toList();
    }

    public List<CfgEdge> incomingEdges(BasicBlock block) {
        requireBlock(block);
        return edges.stream().filter(edge -> edge.target().equals(block)).toList();
    }

    public List<BasicBlock> successors(BasicBlock block) {
        return outgoingEdges(block).stream().map(CfgEdge::target).distinct().toList();
    }

    public List<BasicBlock> predecessors(BasicBlock block) {
        return incomingEdges(block).stream().map(CfgEdge::source).distinct().toList();
    }

    public Optional<BasicBlock> blockContaining(Statement statement) {
        Objects.requireNonNull(statement, "statement");
        return blocks.stream()
                .filter(block -> block.statements().stream()
                        .anyMatch(candidate -> candidate == statement || candidate.equals(statement)))
                .findFirst();
    }

    public Set<BasicBlock> reachableBlocks() {
        Set<BasicBlock> reachable = new LinkedHashSet<>();
        ArrayDeque<BasicBlock> work = new ArrayDeque<>();
        work.add(entry);
        while (!work.isEmpty()) {
            BasicBlock block = work.removeFirst();
            if (reachable.add(block)) {
                successors(block).stream()
                        .filter(successor -> !reachable.contains(successor))
                        .forEach(work::addLast);
            }
        }
        return Set.copyOf(reachable);
    }

    public List<CfgEdge> edgesBetween(BasicBlock source, BasicBlock target) {
        requireBlock(source);
        requireBlock(target);
        List<CfgEdge> matches = new ArrayList<>();
        for (CfgEdge edge : edges) {
            if (edge.source().equals(source) && edge.target().equals(target)) {
                matches.add(edge);
            }
        }
        return List.copyOf(matches);
    }

    private void requireBlock(BasicBlock block) {
        Objects.requireNonNull(block, "block");
        if (!blocks.contains(block)) {
            throw new IllegalArgumentException("Block does not belong to this graph: " + block.id());
        }
    }
}
