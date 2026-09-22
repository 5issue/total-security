package policy.authn11.helper;

import jakarta.persistence.Entity;
import org.springframework.data.jpa.repository.JpaRepository;

@Entity
class HelperRefreshTokenEntity {
    String token;

    HelperRefreshTokenEntity(String token) {
        this.token = token;
    }
}

interface HelperRefreshTokenRepository extends JpaRepository<HelperRefreshTokenEntity, Long> {
    <S extends HelperRefreshTokenEntity> S save(S entity);
}

class SameClassPositive {
    HelperRefreshTokenRepository repository;

    void store(String refreshToken) {
        repository.save(new HelperRefreshTokenEntity(identity(refreshToken)));
    }

    String identity(String value) {
        return value;
    }
}
