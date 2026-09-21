package fixtures.authn11.unsafe;

import jakarta.persistence.Entity;
import org.springframework.data.jpa.repository.JpaRepository;

@Entity
class RefreshTokenEntity {
    String token;
    RefreshTokenEntity(String token) { this.token = token; }
}

interface RefreshTokenRepository {
    <S extends RefreshTokenEntity> S save(S entity);
}

interface RefreshTokenJpaRepository
        extends JpaRepository<RefreshTokenEntity, Long>, RefreshTokenRepository {
}

class RefreshTokenHasher {
    String hash(String rawToken) {
        return rawToken;
    }
}

class UnsafeHasherService {
    RefreshTokenRepository repository;
    RefreshTokenHasher refreshTokenHasher;

    void unverifiedHash(String refreshToken) {
        repository.save(new RefreshTokenEntity(refreshTokenHasher.hash(refreshToken)));
    }
}
