package fixtures.authn11.tryprojection.ifmutation;

import jakarta.persistence.Entity;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.springframework.data.jpa.repository.JpaRepository;

@Entity
class RefreshTokenEntity {
    String token;

    RefreshTokenEntity(String token) {
        this.token = token;
    }
}

interface RefreshTokenRepository {
    <S extends RefreshTokenEntity> S save(S entity);
}

interface RefreshTokenJpaRepository
        extends JpaRepository<RefreshTokenEntity, Long>, RefreshTokenRepository {
}

class RefreshTokenHasher {
    String hash(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(rawToken.getBytes(StandardCharsets.UTF_8));
            byte[] raw = rawToken.getBytes(StandardCharsets.UTF_8);
            if (raw.length == digest.length) {
                System.arraycopy(raw, 0, digest, 0, digest.length);
            }
            return HexFormat.of().formatHex(digest);
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }
}

class IfMutationStorageService {
    RefreshTokenRepository repository;
    RefreshTokenHasher hasher;

    void store(String refreshToken) {
        repository.save(new RefreshTokenEntity(hasher.hash(refreshToken)));
    }
}
