package fixtures.authn11.hasher.reassigneddigest;

import jakarta.persistence.Entity;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.springframework.data.jpa.repository.JpaRepository;

@Entity
class ReassignedDigestRefreshTokenEntity {
    String token;

    ReassignedDigestRefreshTokenEntity(String token) {
        this.token = token;
    }
}

interface ReassignedDigestRefreshTokenRepository {
    <S extends ReassignedDigestRefreshTokenEntity> S save(S entity);
}

interface ReassignedDigestRefreshTokenJpaRepository
        extends JpaRepository<ReassignedDigestRefreshTokenEntity, Long>,
        ReassignedDigestRefreshTokenRepository {
}

class RefreshTokenHasher {
    String hash(String rawToken) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(rawToken.getBytes(StandardCharsets.UTF_8));
        digest = rawToken.getBytes(StandardCharsets.UTF_8);
        return HexFormat.of().formatHex(digest);
    }
}

class ReassignedDigestStorageService {
    ReassignedDigestRefreshTokenRepository repository;
    RefreshTokenHasher hasher;

    void store(String refreshToken) throws Exception {
        repository.save(new ReassignedDigestRefreshTokenEntity(hasher.hash(refreshToken)));
    }
}
