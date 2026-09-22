package fixtures.svc05;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import lombok.Builder;
import org.springframework.amqp.core.MessagePostProcessor;
import org.springframework.amqp.rabbit.connection.CorrelationData;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpHeaders;

class Svc05BrokerMessageFixture {
    RabbitTemplate rabbitTemplate;
    ApplicationEventPublisher applicationEventPublisher;
    ObjectMapper objectMapper;
    EmailService emailService;
    CustomBroker customBroker;
    TokenHelper tokenHelper;
    RefreshTokenHasher refreshTokenHasher;
    FakeHasher fakeHasher;
    JwtTokenProvider jwtTokenProvider;

    void directAccess(String accessToken) {
        rabbitTemplate.convertAndSend("events", "auth.access", accessToken);
    }

    void directRefresh(String refreshToken) {
        rabbitTemplate.convertAndSend("events", "auth.refresh", refreshToken);
    }

    void alias(String accessToken) {
        String value = accessToken;
        rabbitTemplate.convertAndSend("events", "auth.alias", value);
    }

    void assignment(String accessToken) {
        String value;
        value = accessToken;
        rabbitTemplate.convertAndSend("events", "auth.assignment", value);
    }

    void base64(String accessToken) {
        String encoded = Base64.getEncoder().encodeToString(
                accessToken.getBytes(StandardCharsets.UTF_8));
        rabbitTemplate.convertAndSend("events", "auth.base64", encoded);
    }

    void dtoConstructor(Long userId, String accessToken) {
        TokenMessage message = new TokenMessage(userId, accessToken);
        rabbitTemplate.convertAndSend("events", "auth.dto", message);
    }

    void recordPayload(Long userId, String accessToken) {
        rabbitTemplate.convertAndSend(
                "events", "auth.record", new TokenRecord(userId, accessToken));
    }

    void lombokBuilder(Long userId, String accessToken) {
        LombokMessage message = LombokMessage.builder()
                .userId(userId)
                .accessToken(accessToken)
                .build();
        rabbitTemplate.convertAndSend("events", "auth.builder", message);
    }

    void jsonSerialization(Long userId, String accessToken) throws Exception {
        String json = objectMapper.writeValueAsString(new TokenRecord(userId, accessToken));
        rabbitTemplate.convertAndSend("events", "auth.json", json);
    }

    void sameClassHelper(String accessToken) {
        rabbitTemplate.convertAndSend("events", "auth.same", payloadToken(accessToken));
    }

    String payloadToken(String accessToken) {
        return accessToken;
    }

    void crossClassHelper(String accessToken) {
        rabbitTemplate.convertAndSend("events", "auth.cross", tokenHelper.forward(accessToken));
    }

    void mixedPayload(Long userId, String accessToken) {
        rabbitTemplate.convertAndSend(
                "events", "auth.mixed", new TokenRecord(userId, accessToken));
    }

    void multipleTokens(String accessToken, String refreshToken) {
        rabbitTemplate.convertAndSend(
                "events", "auth.multiple", new MultipleTokenRecord(accessToken, refreshToken));
    }

    void issuedToken(Long userId) {
        IssuedToken issued = jwtTokenProvider.issueAccessToken(userId, "USER");
        rabbitTemplate.convertAndSend("events", "auth.issued", issued.token());
    }

    void authorizationHeader(HttpServletRequest request) {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        String withoutBearer = authorization.substring(7);
        String token = withoutBearer.trim();
        rabbitTemplate.convertAndSend("events", "auth.header", token);
    }

    void identifierOnly(Long userId, Long orderId) {
        rabbitTemplate.convertAndSend(
                "events", "business.ids", new IdentifierMessage(userId, orderId, "LOGIN"));
    }

    void accessTokenNotPublished(String accessToken, Long userId) {
        rabbitTemplate.convertAndSend(
                "events", "business.user", new IdentifierMessage(userId, 1L, "LOGIN"));
    }

    void excludedTokens(
            String deviceToken,
            String pushToken,
            String verificationToken,
            String emailVerificationToken) {
        rabbitTemplate.convertAndSend("events", "device", deviceToken);
        rabbitTemplate.convertAndSend("events", "push", pushToken);
        rabbitTemplate.convertAndSend("events", "verification", verificationToken);
        rabbitTemplate.convertAndSend("events", "email-verification", emailVerificationToken);
    }

    void metadataIdentifiers(
            String accessTokenMetadata,
            String jwtConfigName,
            String authorizationTokenType) {
        rabbitTemplate.convertAndSend("events", "metadata.access", accessTokenMetadata);
        rabbitTemplate.convertAndSend("events", "metadata.jwt", jwtConfigName);
        rabbitTemplate.convertAndSend("events", "metadata.authorization", authorizationTokenType);
    }

    void directBearer(String bearerToken) {
        rabbitTemplate.convertAndSend("events", "auth.bearer", bearerToken);
    }

    void directAuthorization(String authorizationToken) {
        rabbitTemplate.convertAndSend("events", "auth.authorization", authorizationToken);
    }

    void directJwt(String jwt) {
        rabbitTemplate.convertAndSend("events", "auth.jwt", jwt);
    }

    void nonBrokerSend(String accessToken) {
        emailService.send(accessToken);
        customBroker.convertAndSend("events", "custom", accessToken);
    }

    void inProcessEvent(String accessToken) {
        applicationEventPublisher.publishEvent(accessToken);
    }

    void routingKeyCallbackOverload(
            String accessToken, MessagePostProcessor messagePostProcessor) {
        rabbitTemplate.convertAndSend("auth.route", accessToken, messagePostProcessor);
    }

    void routingKeyCorrelationOverload(
            String accessToken,
            MessagePostProcessor messagePostProcessor,
            CorrelationData correlationData) {
        rabbitTemplate.convertAndSend(
                "auth.route", accessToken, messagePostProcessor, correlationData);
    }

    void exchangePostProcessorOverload(
            String accessToken, MessagePostProcessor messagePostProcessor) {
        rabbitTemplate.convertAndSend(
                "events", "auth.exchange-four", accessToken, messagePostProcessor);
    }

    void exchangeCorrelationOverload(
            String accessToken,
            MessagePostProcessor messagePostProcessor,
            CorrelationData correlationData) {
        rabbitTemplate.convertAndSend(
                "events", "auth.exchange-five", accessToken,
                messagePostProcessor, correlationData);
    }

    void ambiguousLambdaOverload(String accessToken) {
        rabbitTemplate.convertAndSend("auth.route", accessToken, message -> message);
    }

    void manualBuilderDiscard(String accessToken, Long userId) {
        ManualMessage message = ManualMessage.builder()
                .accessToken(accessToken)
                .userId(userId)
                .build();
        rabbitTemplate.convertAndSend("events", "auth.manual", message);
    }

    void constructorDiscard(String accessToken, Long userId) {
        rabbitTemplate.convertAndSend(
                "events", "auth.discard", new DiscardingMessage(userId, accessToken));
    }

    void constructorOverwrite(String accessToken) {
        rabbitTemplate.convertAndSend(
                "events", "auth.overwrite", new OverwritingMessage(accessToken));
    }

    void exactHashRemovesRawMeaning(String refreshToken) {
        String hashed = refreshTokenHasher.hash(refreshToken);
        rabbitTemplate.convertAndSend("events", "auth.hashed", hashed);
    }

    void nameOnlyHashDoesNotRemoveRawMeaning(String accessToken) {
        rabbitTemplate.convertAndSend("events", "auth.fake-hash", fakeHasher.hash(accessToken));
    }

    void issuerMetadataIsNotToken(Long userId) {
        IssuedToken issued = jwtTokenProvider.issueRefreshToken(userId, "USER");
        rabbitTemplate.convertAndSend("events", "auth.jti", issued.jti());
    }

    void manuallyConstructedIssuerRecordIsNotSource() {
        IssuedToken issued = new IssuedToken("business-value", Instant.EPOCH, "id");
        rabbitTemplate.convertAndSend("events", "business.token", issued.token());
    }

    void redactedEvidence(String accessToken) {
        String wrapped = "Bearer eyJhbGciOiJIUzI1NiJ9." + accessToken;
        rabbitTemplate.convertAndSend("events", "auth.redacted", wrapped);
    }
}

record TokenRecord(Long userId, String accessToken) {}

record MultipleTokenRecord(String accessToken, String refreshToken) {}

record IdentifierMessage(Long userId, Long orderId, String eventType) {}

record IssuedToken(String token, Instant expiresAt, String jti) {}

class TokenMessage {
    Long userId;
    String accessToken;

    TokenMessage(Long userId, String accessToken) {
        this.userId = userId;
        this.accessToken = accessToken;
    }
}

class LombokMessage {
    Long userId;
    String accessToken;

    @Builder
    LombokMessage(Long userId, String accessToken) {
        this.userId = userId;
        this.accessToken = accessToken;
    }
}

class ManualMessage {
    static ManualBuilder builder() {
        return new ManualBuilder();
    }
}

class ManualBuilder {
    Long userId;

    ManualBuilder accessToken(String accessToken) {
        return this;
    }

    ManualBuilder userId(Long userId) {
        this.userId = userId;
        return this;
    }

    IdentifierMessage build() {
        return new IdentifierMessage(userId, 1L, "LOGIN");
    }
}

class DiscardingMessage {
    Long userId;

    DiscardingMessage(Long userId, String accessToken) {
        this.userId = userId;
    }
}

class OverwritingMessage {
    String accessToken;

    OverwritingMessage(String accessToken) {
        this.accessToken = accessToken;
        this.accessToken = "removed";
    }
}

class TokenHelper {
    String forward(String accessToken) {
        return accessToken;
    }
}

class EmailService {
    void send(String value) {}
}

class CustomBroker {
    void convertAndSend(String exchange, String routingKey, Object payload) {}
}

class FakeHasher {
    String hash(String value) {
        return value;
    }
}

class JwtTokenProvider {
    IssuedToken issueAccessToken(Long userId, String role) {
        return null;
    }

    IssuedToken issueRefreshToken(Long userId, String role) {
        return null;
    }
}

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
