package com.totalsecurity.sast.detector.authn;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

final class Authn11Names {
    private static final Set<String> HASH_WORDS = Set.of("digest", "encoded", "hash", "hashed");

    private Authn11Names() {}

    static boolean isRawRefreshTokenIdentifier(String value) {
        Set<String> words = words(value);
        return words.contains("refresh") && words.contains("token")
                && words.stream().noneMatch(HASH_WORDS::contains);
    }

    static boolean isRefreshTokenType(String value) {
        Set<String> words = words(simpleName(value));
        return words.contains("refresh") && words.contains("token");
    }

    static boolean isRefreshTokenRepository(String value) {
        Set<String> words = words(simpleName(value));
        return words.contains("refresh") && words.contains("token")
                && words.contains("repository");
    }

    static boolean isTokenStorageName(String value) {
        return words(value).contains("token");
    }

    static String simpleName(String value) {
        String normalized = value;
        int generic = normalized.indexOf('<');
        if (generic >= 0) {
            normalized = normalized.substring(0, generic);
        }
        int separator = Math.max(normalized.lastIndexOf('.'), normalized.lastIndexOf('$'));
        return separator < 0 ? normalized : normalized.substring(separator + 1);
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
            current.append(String.valueOf(character).toLowerCase(Locale.ROOT));
        }
        flush(current, parsed);
        return Set.copyOf(new LinkedHashSet<>(parsed));
    }

    private static void flush(StringBuilder current, List<String> words) {
        if (current.length() > 0) {
            words.add(current.toString());
            current.setLength(0);
        }
    }
}
