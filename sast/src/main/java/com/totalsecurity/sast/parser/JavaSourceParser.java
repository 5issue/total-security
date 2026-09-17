package com.totalsecurity.sast.parser;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Objects;
import org.treesitter.TSLanguage;
import org.treesitter.TSParser;
import org.treesitter.TSTree;
import org.treesitter.TreeSitterJava;

/** Parses Java source files with Tree-sitter Java. */
public final class JavaSourceParser implements AutoCloseable {
    private final TSLanguage javaLanguage;
    private final TSParser parser;

    public JavaSourceParser() {
        javaLanguage = new TreeSitterJava();
        parser = new TSParser();
        if (!parser.setLanguage(javaLanguage)) {
            parser.close();
            javaLanguage.close();
            throw new IllegalStateException("Tree-sitter rejected the bundled Java grammar");
        }
    }

    public ParsedJavaFile parse(Path javaFile) throws IOException {
        return parse(javaFile, StandardCharsets.UTF_8);
    }

    public ParsedJavaFile parse(Path javaFile, Charset charset) throws IOException {
        Objects.requireNonNull(javaFile, "javaFile");
        Objects.requireNonNull(charset, "charset");
        Path normalizedPath = javaFile.toAbsolutePath().normalize();
        if (!normalizedPath.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".java")) {
            throw new IllegalArgumentException("Expected a .java file: " + normalizedPath);
        }
        if (!Files.isRegularFile(normalizedPath)) {
            throw new IOException("Java source file does not exist: " + normalizedPath);
        }

        byte[] fileBytes = Files.readAllBytes(normalizedPath);
        String source = new String(fileBytes, charset);
        byte[] sourceBytes = source.getBytes(StandardCharsets.UTF_8);
        TSTree tree = parser.parseString(null, source);
        if (tree == null) {
            throw new IllegalStateException("Tree-sitter did not produce a syntax tree");
        }
        return new ParsedJavaFile(normalizedPath, sourceBytes, tree);
    }

    @Override
    public void close() {
        parser.close();
        javaLanguage.close();
    }
}
