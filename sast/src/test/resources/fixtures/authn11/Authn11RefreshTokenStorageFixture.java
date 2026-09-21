package fixtures.authn11;

import jakarta.persistence.Entity;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import lombok.Builder;
import org.springframework.data.jpa.repository.JpaRepository;

@Entity
class RefreshTokenEntity {
    private String token;
    private String tokenHash;
    private String rawToken;

    RefreshTokenEntity(String token) {
        this.token = token;
    }

    @Builder
    RefreshTokenEntity(String token, String tokenHash, String rawToken) {
        this.token = token;
        this.tokenHash = tokenHash;
        this.rawToken = rawToken;
    }
}

interface RefreshTokenRepository {
    <S extends RefreshTokenEntity> S save(S entity);
}

interface RefreshTokenJpaRepository
        extends JpaRepository<RefreshTokenEntity, Long>, RefreshTokenRepository {
}

class RefreshTokenHasher {
    private static final String ALGORITHM = "SHA-256";

    String hash(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance(ALGORITHM)
                    .digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (Exception exception) {
            throw new IllegalStateException(
                    "%s algorithm is unavailable".formatted(ALGORITHM), exception);
        }
    }
}

record IssuedToken(String token, Instant expiresAt, Duration ttl, String jti) {
}

class JwtTokenProvider {
    IssuedToken issueRefreshToken(Long userId, String role) {
        return new IssuedToken("runtime-token", Instant.now(), Duration.ofDays(1), "id");
    }
}

class RefreshTokenIdentity {
    String forward(String value) {
        return value;
    }
}

class RefreshTokenStorageService {
    private RefreshTokenRepository repository;
    private RefreshTokenHasher refreshTokenHasher;
    private JwtTokenProvider jwtTokenProvider;
    private RefreshTokenIdentity identity;

    void directRaw(String refreshToken) {
        repository.save(new RefreshTokenEntity(refreshToken));
    }

    void localAlias(String refreshToken) {
        String token = refreshToken;
        repository.save(new RefreshTokenEntity(token));
    }

    void assignedRaw(String refreshToken) {
        String stored;
        stored = refreshToken;
        repository.save(new RefreshTokenEntity(stored));
    }

    void sameClassRaw(String refreshToken) {
        String stored = identityRefreshToken(refreshToken);
        repository.save(new RefreshTokenEntity(stored));
    }

    private String identityRefreshToken(String value) {
        return value;
    }

    void crossClassRaw(String refreshToken) {
        String stored = identity.forward(refreshToken);
        repository.save(new RefreshTokenEntity(stored));
    }

    void hashedBeforePersistence(String refreshToken) {
        String hash = refreshTokenHasher.hash(refreshToken);
        repository.save(new RefreshTokenEntity(hash));
    }

    void hashComputedButRawStored(String refreshToken) {
        String hash = refreshTokenHasher.hash(refreshToken);
        repository.save(new RefreshTokenEntity(refreshToken));
    }

    void base64Only(String refreshToken) {
        String encoded = Base64.getEncoder().encodeToString(
                refreshToken.getBytes(StandardCharsets.UTF_8));
        repository.save(new RefreshTokenEntity(encoded));
    }

    void accessTokenPersistence(String accessToken) {
        repository.save(new RefreshTokenEntity(accessToken));
    }

    void arbitraryTokenPersistence(String verificationToken) {
        String token = verificationToken;
        repository.save(new RefreshTokenEntity(token));
    }

    String noPersistence(String refreshToken) {
        return refreshToken;
    }

    void hashedName(String refreshToken) {
        String refreshTokenHash = refreshTokenHasher.hash(refreshToken);
        repository.save(new RefreshTokenEntity(refreshTokenHash));
    }

    String responseOnly(String refreshToken) {
        return "cookie=" + refreshToken;
    }

    void mixedRawAndHash(String refreshToken) {
        repository.save(RefreshTokenEntity.builder()
                .tokenHash(refreshTokenHasher.hash(refreshToken))
                .rawToken(refreshToken)
                .build());
    }

    void backendStyleHashed(Long userId) {
        IssuedToken refresh = jwtTokenProvider.issueRefreshToken(userId, "USER");
        repository.save(RefreshTokenEntity.builder()
                .token(refreshTokenHasher.hash(refresh.token()))
                .build());
    }

    void backendStyleRaw(Long userId) {
        IssuedToken refresh = jwtTokenProvider.issueRefreshToken(userId, "USER");
        repository.save(RefreshTokenEntity.builder()
                .token(refresh.token())
                .build());
    }
}
