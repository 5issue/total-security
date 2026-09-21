package fixtures.authn11.tryprojection.customgetbytes;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

class Helper {
    byte[] getBytes() {
        return new byte[0];
    }
}

class RefreshTokenHasher {
    Helper helper;

    String hash(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(rawToken.getBytes(StandardCharsets.UTF_8));
            byte[] ignored = helper.getBytes();
            return HexFormat.of().formatHex(digest);
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }
}
