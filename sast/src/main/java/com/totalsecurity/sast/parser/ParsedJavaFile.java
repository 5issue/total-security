package com.totalsecurity.sast.parser;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Objects;
import org.treesitter.TSNode;
import org.treesitter.TSTree;

/** A parsed Java file and the UTF-8 source bytes used to create its syntax tree. */
public final class ParsedJavaFile implements AutoCloseable {
    private final Path path;
    private final byte[] sourceBytes;
    private final TSTree tree;

    ParsedJavaFile(Path path, byte[] sourceBytes, TSTree tree) {
        this.path = Objects.requireNonNull(path, "path");
        this.sourceBytes = Arrays.copyOf(sourceBytes, sourceBytes.length);
        this.tree = Objects.requireNonNull(tree, "tree");
    }

    public Path path() {
        return path;
    }

    public TSNode rootNode() {
        return tree.getRootNode();
    }

    public boolean hasSyntaxErrors() {
        return rootNode().hasError();
    }

    public String sourceText(TSNode node) {
        Objects.requireNonNull(node, "node");
        int start = node.getStartByte();
        int end = node.getEndByte();
        if (start < 0 || end < start || end > sourceBytes.length) {
            throw new IllegalArgumentException("Node byte range is outside the parsed source");
        }
        return new String(sourceBytes, start, end - start, StandardCharsets.UTF_8);
    }

    @Override
    public void close() {
        tree.close();
    }
}

