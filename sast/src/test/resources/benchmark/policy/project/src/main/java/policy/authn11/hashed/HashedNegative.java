package policy.authn11.hashed;

import jakarta.persistence.Entity;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.springframework.data.jpa.repository.JpaRepository;

@Entity
class HashedRefreshTokenEntity {
    String tokenHash;

    HashedRefreshTokenEntity(String tokenHash) {
        this.tokenHash = tokenHash;
    }
}

interface HashedRefreshTokenRepository extends JpaRepository<HashedRefreshTokenEntity, Long> {
    <S extends HashedRefreshTokenEntity> S save(S entity);
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

class HashedNegative {
    HashedRefreshTokenRepository repository;
    RefreshTokenHasher hasher;

    void store(String refreshToken) {
        repository.save(new HashedRefreshTokenEntity(hasher.hash(refreshToken)));
    }
}
