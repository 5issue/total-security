package policy.authn11.access;

import jakarta.persistence.Entity;
import org.springframework.data.jpa.repository.JpaRepository;

@Entity
class AccessRefreshTokenEntity {
    String token;

    AccessRefreshTokenEntity(String token) {
        this.token = token;
    }
}

interface AccessRefreshTokenRepository extends JpaRepository<AccessRefreshTokenEntity, Long> {
    <S extends AccessRefreshTokenEntity> S save(S entity);
}

class AccessTokenNegative {
    AccessRefreshTokenRepository repository;

    void store(String accessToken) {
        repository.save(new AccessRefreshTokenEntity(accessToken));
    }
}
