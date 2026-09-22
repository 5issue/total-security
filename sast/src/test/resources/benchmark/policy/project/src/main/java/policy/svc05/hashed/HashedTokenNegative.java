package policy.svc05.hashed;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.springframework.amqp.rabbit.core.RabbitTemplate;

class RefreshTokenHasher {
    String hash(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }
}

class HashedTokenNegative {
    RabbitTemplate rabbitTemplate;
    RefreshTokenHasher hasher;

    void publish(String refreshToken) {
        String hashed = "" + hasher.hash(refreshToken);
        rabbitTemplate.convertAndSend(
                "events", "auth.hashed", hashed);
    }
}
