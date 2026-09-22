package policy.authn11.direct;

import jakarta.persistence.Entity;
import org.springframework.data.jpa.repository.JpaRepository;

@Entity
class DirectRefreshTokenEntity {
    String token;

    DirectRefreshTokenEntity(String token) {
        this.token = token;
    }
}

interface DirectRefreshTokenRepository extends JpaRepository<DirectRefreshTokenEntity, Long> {
    <S extends DirectRefreshTokenEntity> S save(S entity);
}

class DirectRawPositive {
    DirectRefreshTokenRepository repository;

    void store(String refreshToken) {
        repository.save(new DirectRefreshTokenEntity(refreshToken));
    }
}
