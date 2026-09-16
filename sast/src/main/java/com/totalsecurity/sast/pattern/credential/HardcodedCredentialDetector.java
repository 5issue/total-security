package com.totalsecurity.sast.pattern.credential;

import com.totalsecurity.sast.finding.FindingSeverity;
import com.totalsecurity.sast.finding.PatternFinding;
import com.totalsecurity.sast.finding.PatternOccurrenceKind;
import com.totalsecurity.sast.ir.AssignmentInfo;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.VariableInfo;
import com.totalsecurity.sast.ir.VariableKind;
import com.totalsecurity.sast.ir.expression.Expression;
import com.totalsecurity.sast.ir.expression.FieldAccessExpression;
import com.totalsecurity.sast.ir.expression.Literal;
import com.totalsecurity.sast.ir.expression.ParenthesizedExpression;
import com.totalsecurity.sast.ir.expression.VariableReference;
import com.totalsecurity.sast.pattern.PatternDetector;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Detects non-empty string literals structurally assigned to supported sensitive identifiers. */
public final class HardcodedCredentialDetector implements PatternDetector {
    public static final String RULE_ID = "HARDCODED_CREDENTIAL";
    public static final String VULNERABILITY_TYPE = "Hardcoded Credential";
    public static final String CWE = "CWE-798";
    public static final FindingSeverity SEVERITY = FindingSeverity.HIGH;

    private static final Set<String> SENSITIVE_IDENTIFIERS = Set.of(
            "password",
            "passwd",
            "pwd",
            "secret",
            "secret key",
            "client secret",
            "api key",
            "token",
            "access token",
            "auth token",
            "private key");

    @Override
    public List<PatternFinding> detect(JavaFileInfo file) {
        Objects.requireNonNull(file, "file");
        LinkedHashMap<OccurrenceKey, PatternFinding> findings = new LinkedHashMap<>();
        for (ClassInfo type : file.types()) {
            for (VariableInfo field : type.fields()) {
                addDeclaration(field, findings);
            }
            for (MethodInfo method : type.methods()) {
                for (VariableInfo local : method.localVariables()) {
                    addDeclaration(local, findings);
                }
                for (AssignmentInfo assignment : method.assignments()) {
                    addAssignment(assignment, findings);
                }
            }
        }
        return List.copyOf(findings.values());
    }

    static boolean isSensitiveIdentifier(String identifier) {
        return SENSITIVE_IDENTIFIERS.contains(normalizeIdentifier(identifier));
    }

    static String normalizeIdentifier(String identifier) {
        Objects.requireNonNull(identifier, "identifier");
        List<String> words = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (int index = 0; index < identifier.length(); index++) {
            char character = identifier.charAt(index);
            if (!Character.isLetterOrDigit(character)) {
                flushWord(current, words);
                continue;
            }
            if (current.length() > 0 && Character.isUpperCase(character)) {
                char previous = identifier.charAt(index - 1);
                boolean lowerToUpper = Character.isLowerCase(previous) || Character.isDigit(previous);
                boolean acronymBoundary = Character.isUpperCase(previous)
                        && index + 1 < identifier.length()
                        && Character.isLowerCase(identifier.charAt(index + 1));
                if (lowerToUpper || acronymBoundary) {
                    flushWord(current, words);
                }
            }
            current.append(Character.toLowerCase(character));
        }
        flushWord(current, words);
        return String.join(" ", words).toLowerCase(Locale.ROOT);
    }

    private static void flushWord(StringBuilder current, List<String> words) {
        if (current.length() > 0) {
            words.add(current.toString());
            current.setLength(0);
        }
    }

    private void addDeclaration(
            VariableInfo variable, LinkedHashMap<OccurrenceKey, PatternFinding> findings) {
        if (!isSensitiveIdentifier(variable.name())) {
            return;
        }
        variable.initializer().flatMap(this::nonBlankStringLiteral).ifPresent(literal -> {
            PatternOccurrenceKind kind = variable.kind() == VariableKind.FIELD
                    ? PatternOccurrenceKind.FIELD_DECLARATION
                    : PatternOccurrenceKind.LOCAL_DECLARATION;
            addFinding(variable.name(), kind, literal, findings);
        });
    }

    private void addAssignment(
            AssignmentInfo assignment, LinkedHashMap<OccurrenceKey, PatternFinding> findings) {
        if (!assignment.operator().equals("=")) {
            return;
        }
        Optional<String> identifier = assignedIdentifier(assignment.left());
        if (identifier.isEmpty() || !isSensitiveIdentifier(identifier.orElseThrow())) {
            return;
        }
        nonBlankStringLiteral(assignment.right()).ifPresent(literal ->
                addFinding(identifier.orElseThrow(), PatternOccurrenceKind.ASSIGNMENT, literal, findings));
    }

    private Optional<String> assignedIdentifier(Expression left) {
        return switch (left) {
            case VariableReference reference -> Optional.of(reference.name());
            case FieldAccessExpression field -> Optional.of(field.fieldName());
            case ParenthesizedExpression parenthesized -> assignedIdentifier(parenthesized.expression());
            default -> Optional.empty();
        };
    }

    private Optional<Literal> nonBlankStringLiteral(Expression expression) {
        if (expression instanceof ParenthesizedExpression parenthesized) {
            return nonBlankStringLiteral(parenthesized.expression());
        }
        if (!(expression instanceof Literal literal) || !literal.kind().equals("string_literal")) {
            return Optional.empty();
        }
        return hasNonWhitespaceContent(literal.source()) ? Optional.of(literal) : Optional.empty();
    }

    private boolean hasNonWhitespaceContent(String source) {
        if (source.length() < 2 || source.charAt(0) != '"' || source.charAt(source.length() - 1) != '"') {
            return false;
        }
        for (int index = 1; index < source.length() - 1; index++) {
            char character = source.charAt(index);
            if (character != '\\') {
                if (!Character.isWhitespace(character)) {
                    return true;
                }
                continue;
            }
            if (++index >= source.length() - 1) {
                return true;
            }
            char escaped = source.charAt(index);
            if (escaped != 't' && escaped != 'n' && escaped != 'r' && escaped != 'f' && escaped != 's') {
                return true;
            }
        }
        return false;
    }

    private void addFinding(
            String identifier,
            PatternOccurrenceKind occurrenceKind,
            Literal literal,
            LinkedHashMap<OccurrenceKey, PatternFinding> findings) {
        SourceLocation location = literal.location();
        OccurrenceKey key = new OccurrenceKey(RULE_ID, location);
        String evidence = "Hardcoded string literal assigned to sensitive identifier '"
                + identifier + "' (value redacted)";
        findings.putIfAbsent(key, new PatternFinding(
                RULE_ID,
                VULNERABILITY_TYPE,
                CWE,
                SEVERITY,
                location,
                identifier,
                occurrenceKind,
                literal.kind(),
                evidence));
    }

    private record OccurrenceKey(String ruleId, SourceLocation location) {}
}
