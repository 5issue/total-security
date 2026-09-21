package fixtures.authn11.hasher.ambiguousalgorithm;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

class RefreshTokenHasher {
    String hash(String rawToken) throws Exception {
        String algorithm;
        if (rawToken.isEmpty()) {
            algorithm = "SHA-256";
        } else {
            algorithm = "SHA-1";
        }
        byte[] digest = MessageDigest.getInstance(algorithm)
                .digest(rawToken.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(digest);
    }
}
