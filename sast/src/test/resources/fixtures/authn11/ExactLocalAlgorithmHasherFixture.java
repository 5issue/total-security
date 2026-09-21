package fixtures.authn11.hasher.exactlocalalgorithm;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

class RefreshTokenHasher {
    String hash(String rawToken) throws Exception {
        String algorithm = "SHA-256";
        byte[] digest = MessageDigest.getInstance(algorithm)
                .digest(rawToken.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(digest);
    }
}
