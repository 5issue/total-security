package com.totalsecurity.sast.parser;

import java.io.PrintStream;
import java.util.Objects;
import org.treesitter.TSNode;
import org.treesitter.TSPoint;

/** Prints Tree-sitter node types, positions, and concise source text. */
public final class SyntaxTreePrinter {
    private static final int MAX_TEXT_LENGTH = 80;

    public void print(ParsedJavaFile parsedFile, PrintStream output) {
        Objects.requireNonNull(parsedFile, "parsedFile");
        Objects.requireNonNull(output, "output");
        printNode(parsedFile, parsedFile.rootNode(), output, 0);
    }

    private void printNode(ParsedJavaFile parsedFile, TSNode node, PrintStream output, int depth) {
        TSPoint start = node.getStartPoint();
        TSPoint end = node.getEndPoint();
        String sourceSuffix = sourceSuffix(parsedFile, node);

        output.printf(
                "%s%s [%d:%d - %d:%d]%s%n",
                "  ".repeat(depth),
                node.getType(),
                start.getRow(),
                start.getColumn(),
                end.getRow(),
                end.getColumn(),
                sourceSuffix);

        for (int index = 0; index < node.getChildCount(); index++) {
            printNode(parsedFile, node.getChild(index), output, depth + 1);
        }
    }

    private String sourceSuffix(ParsedJavaFile parsedFile, TSNode node) {
        if (!node.isNamed() || node.getChildCount() != 0) {
            return "";
        }

        String text = parsedFile.sourceText(node)
                .replace("\\", "\\\\")
                .replace("\r", "\\r")
                .replace("\n", "\\n")
                .replace("\t", "\\t")
                .replace("\"", "\\\"");
        if (text.length() > MAX_TEXT_LENGTH) {
            text = text.substring(0, MAX_TEXT_LENGTH - 3) + "...";
        }
        return " text=\"" + text + "\"";
    }
}

