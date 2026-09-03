package com.totalsecurity.sast.cli;

import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import com.totalsecurity.sast.parser.SyntaxTreePrinter;
import java.nio.file.Path;

/** Command-line entry point for STEP 1 Java syntax-tree inspection. */
public final class SastParserApplication {
    private SastParserApplication() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: sast-parser <path-to-java-file>");
            System.exit(2);
        }

        try (JavaSourceParser parser = new JavaSourceParser();
                ParsedJavaFile parsedFile = parser.parse(Path.of(args[0]))) {
            System.out.println("file: " + parsedFile.path());
            System.out.println("hasSyntaxErrors: " + parsedFile.hasSyntaxErrors());
            new SyntaxTreePrinter().print(parsedFile, System.out);
        }
    }
}

