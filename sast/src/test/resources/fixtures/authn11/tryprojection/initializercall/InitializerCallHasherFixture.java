package fixtures.authn11.tryprojection.initializercall;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

class RefreshTokenHasher {
    String hash(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(rawToken.getBytes(StandardCharsets.UTF_8));
            int ignored = mutate(digest);
            return HexFormat.of().formatHex(digest);
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    private int mutate(byte[] digest) {
        digest[0] = 0;
        return 0;
    }
}
