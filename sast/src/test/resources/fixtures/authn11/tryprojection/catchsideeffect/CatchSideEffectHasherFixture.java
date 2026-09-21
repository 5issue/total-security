package fixtures.authn11.tryprojection.catchsideeffect;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

class RefreshTokenHasher {
    String hash(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (Exception exception) {
            audit(exception);
            throw new IllegalStateException(exception);
        }
    }

    private void audit(Exception exception) {
    }
}
