package com.totalsecurity.sast.pattern.authn;

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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** AUTHN-06 source check for hardcoded authentication signing material. */
public final class Authn06HardcodedSigningMaterialDetector implements PatternDetector {
    public static final String RULE_ID = "AUTHN_06_HARDCODED_SIGNING_MATERIAL";
    public static final String CHECKLIST_ID = "AUTHN-06";
    public static final String VULNERABILITY_TYPE = "Hardcoded Signing Key Material";
    public static final FindingSeverity SEVERITY = FindingSeverity.HIGH;

    private static final Set<String> SIGNING_CONTEXT_WORDS = Set.of(
            "auth", "authentication", "jws", "jwt", "signature", "signer", "signing", "token");
    private static final Set<String> MATERIAL_WORDS = Set.of("key", "secret");
    private static final Set<String> NON_MATERIAL_IDENTIFIER_WORDS = Set.of(
            "algorithm", "alias", "arn", "cert", "certificate", "id", "identifier",
            "name", "path", "property", "public", "verification", "verify");
    private static final List<PemMarker> PRIVATE_PEM_MARKERS = List.of(
            new PemMarker("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"),
            new PemMarker("-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"),
            new PemMarker("-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----"));
    private static final Set<String> OBVIOUS_PLACEHOLDER_VALUES = Set.of(
            "change-me",
            "changeme",
            "dummy",
            "dummy-secret",
            "dummy-signing-secret",
            "example",
            "example-placeholder",
            "example-secret",
            "example-signing-secret",
            "not-a-real-secret",
            "placeholder",
            "placeholder-secret",
            "placeholder-signing-secret",
            "replace-me",
            "test-only",
            "test-secret",
            "test-signing-secret",
            "todo",
            "your-secret",
            "your-signing-secret");

    @Override
    public List<PatternFinding> detect(JavaFileInfo file) {
        Objects.requireNonNull(file, "file");
        LinkedHashMap<OccurrenceKey, PatternFinding> findings = new LinkedHashMap<>();
        for (ClassInfo type : file.types()) {
            for (VariableInfo field : type.fields()) {
                addDeclaration(type, field, findings);
            }
            for (MethodInfo method : type.methods()) {
                for (VariableInfo local : method.localVariables()) {
                    addDeclaration(type, local, findings);
                }
                for (AssignmentInfo assignment : method.assignments()) {
                    addAssignment(type, assignment, findings);
                }
            }
        }
        return List.copyOf(findings.values());
    }

    private void addDeclaration(
            ClassInfo type,
            VariableInfo variable,
            LinkedHashMap<OccurrenceKey, PatternFinding> findings) {
        variable.initializer().flatMap(this::stringLiteral).ifPresent(literal -> {
            PatternOccurrenceKind occurrence = variable.kind() == VariableKind.FIELD
                    ? PatternOccurrenceKind.FIELD_DECLARATION
                    : PatternOccurrenceKind.LOCAL_DECLARATION;
            classify(type, variable.name(), literal).ifPresent(category ->
                    addFinding(variable.name(), occurrence, literal, category, findings));
        });
    }

    private void addAssignment(
            ClassInfo type,
            AssignmentInfo assignment,
            LinkedHashMap<OccurrenceKey, PatternFinding> findings) {
        if (!assignment.operator().equals("=")) {
            return;
        }
        Optional<String> identifier = assignedIdentifier(assignment.left());
        Optional<Literal> literal = stringLiteral(assignment.right());
        if (identifier.isEmpty() || literal.isEmpty()) {
            return;
        }
        classify(type, identifier.orElseThrow(), literal.orElseThrow()).ifPresent(category ->
                addFinding(
                        identifier.orElseThrow(),
                        PatternOccurrenceKind.ASSIGNMENT,
                        literal.orElseThrow(),
                        category,
                        findings));
    }

    private Optional<MaterialCategory> classify(
            ClassInfo type, String identifier, Literal literal) {
        String content = literalContent(literal.source());
        if (content.isBlank() || isExternalConfigurationPlaceholder(content)) {
            return Optional.empty();
        }
        Optional<PemMarker> completePrivatePem = matchingPrivatePem(content);
        if (containsPrivatePemMarker(content)) {
            if (completePrivatePem.isEmpty()
                    || isClearPemExamplePlaceholder(content, completePrivatePem.orElseThrow())) {
                return Optional.empty();
            }
            return Optional.of(MaterialCategory.PRIVATE_KEY_PEM);
        }
        if (isClearExamplePlaceholder(content)
                || containsPublicMaterialMarker(content)
                || !isSigningMaterialIdentifier(type, identifier)) {
            return Optional.empty();
        }
        return Optional.of(MaterialCategory.SIGNING_SECRET);
    }

    private static boolean isSigningMaterialIdentifier(ClassInfo type, String identifier) {
        Set<String> identifierWords = words(identifier);
        if (identifierWords.stream().anyMatch(NON_MATERIAL_IDENTIFIER_WORDS::contains)
                || identifierWords.stream().noneMatch(MATERIAL_WORDS::contains)) {
            return false;
        }
        return identifierWords.stream().anyMatch(SIGNING_CONTEXT_WORDS::contains)
                || words(type.sourceName()).stream().anyMatch(SIGNING_CONTEXT_WORDS::contains);
    }

    private static Set<String> words(String value) {
        List<String> parsed = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!Character.isLetterOrDigit(character)) {
                flush(current, parsed);
                continue;
            }
            if (current.length() > 0 && Character.isUpperCase(character)) {
                char previous = value.charAt(index - 1);
                boolean lowerToUpper = Character.isLowerCase(previous) || Character.isDigit(previous);
                boolean acronymBoundary = Character.isUpperCase(previous)
                        && index + 1 < value.length()
                        && Character.isLowerCase(value.charAt(index + 1));
                if (lowerToUpper || acronymBoundary) {
                    flush(current, parsed);
                }
            }
            current.append(Character.toLowerCase(character));
        }
        flush(current, parsed);
        return Set.copyOf(parsed);
    }

    private static void flush(StringBuilder current, List<String> words) {
        if (current.length() != 0) {
            words.add(current.toString());
            current.setLength(0);
        }
    }

    private Optional<String> assignedIdentifier(Expression expression) {
        return switch (expression) {
            case VariableReference reference -> Optional.of(reference.name());
            case FieldAccessExpression field -> Optional.of(field.fieldName());
            case ParenthesizedExpression parenthesized -> assignedIdentifier(parenthesized.expression());
            default -> Optional.empty();
        };
    }

    private Optional<Literal> stringLiteral(Expression expression) {
        if (expression instanceof ParenthesizedExpression parenthesized) {
            return stringLiteral(parenthesized.expression());
        }
        if (expression instanceof Literal literal && literal.kind().equals("string_literal")) {
            return Optional.of(literal);
        }
        return Optional.empty();
    }

    private static String literalContent(String source) {
        if (source.startsWith("\"\"\"") && source.endsWith("\"\"\"") && source.length() >= 6) {
            return source.substring(3, source.length() - 3);
        }
        if (source.startsWith("\"") && source.endsWith("\"") && source.length() >= 2) {
            return source.substring(1, source.length() - 1);
        }
        return source;
    }

    private static Optional<PemMarker> matchingPrivatePem(String content) {
        String upper = content.toUpperCase(Locale.ROOT);
        return PRIVATE_PEM_MARKERS.stream()
                .filter(marker -> {
                    int beginIndex = upper.indexOf(marker.begin());
                    if (beginIndex < 0) {
                        return false;
                    }
                    int bodyStart = beginIndex + marker.begin().length();
                    int endIndex = upper.indexOf(marker.end(), bodyStart);
                    return endIndex > bodyStart;
                })
                .findFirst();
    }

    private static boolean containsPrivatePemMarker(String content) {
        String upper = content.toUpperCase(Locale.ROOT);
        return PRIVATE_PEM_MARKERS.stream().anyMatch(marker ->
                upper.contains(marker.begin()) || upper.contains(marker.end()));
    }

    private static boolean containsPublicMaterialMarker(String content) {
        String upper = content.toUpperCase(Locale.ROOT);
        return upper.contains("-----BEGIN PUBLIC KEY-----")
                || upper.contains("-----BEGIN RSA PUBLIC KEY-----")
                || upper.contains("-----BEGIN CERTIFICATE-----");
    }

    private static boolean isExternalConfigurationPlaceholder(String content) {
        String stripped = content.strip();
        return stripped.startsWith("${") && stripped.endsWith("}");
    }

    private static boolean isClearExamplePlaceholder(String content) {
        return OBVIOUS_PLACEHOLDER_VALUES.contains(normalizePlaceholder(content));
    }

    private static boolean isClearPemExamplePlaceholder(String content, PemMarker marker) {
        String upper = content.toUpperCase(Locale.ROOT);
        int bodyStart = upper.indexOf(marker.begin()) + marker.begin().length();
        int bodyEnd = upper.indexOf(marker.end(), bodyStart);
        if (bodyEnd < bodyStart) {
            return false;
        }
        return isClearExamplePlaceholder(content.substring(bodyStart, bodyEnd));
    }

    private static String normalizePlaceholder(String content) {
        StringBuilder normalized = new StringBuilder();
        boolean separator = false;
        for (int index = 0; index < content.length(); index++) {
            char current = Character.toLowerCase(content.charAt(index));
            if (current == '_' || Character.isWhitespace(current)) {
                separator = normalized.length() > 0;
                continue;
            }
            if (separator && normalized.charAt(normalized.length() - 1) != '-') {
                normalized.append('-');
            }
            normalized.append(current);
            separator = false;
        }
        int length = normalized.length();
        while (length > 0 && normalized.charAt(length - 1) == '-') {
            normalized.setLength(--length);
        }
        return normalized.toString();
    }

    private static void addFinding(
            String identifier,
            PatternOccurrenceKind occurrence,
            Literal literal,
            MaterialCategory category,
            LinkedHashMap<OccurrenceKey, PatternFinding> findings) {
        SourceLocation location = literal.location();
        OccurrenceKey key = new OccurrenceKey(RULE_ID, location);
        String evidence = CHECKLIST_ID + ": hardcoded " + category.description
                + " assigned to '" + identifier + "' (value redacted)";
        findings.putIfAbsent(key, new PatternFinding(
                RULE_ID,
                VULNERABILITY_TYPE,
                Optional.empty(),
                SEVERITY,
                location,
                identifier,
                occurrence,
                literal.kind(),
                evidence));
    }

    private enum MaterialCategory {
        PRIVATE_KEY_PEM("private-key PEM literal"),
        SIGNING_SECRET("authentication signing secret literal");

        private final String description;

        MaterialCategory(String description) {
            this.description = description;
        }
    }

    private record PemMarker(String begin, String end) {}

    private record OccurrenceKey(String ruleId, SourceLocation location) {}
}
