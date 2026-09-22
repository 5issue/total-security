package policy.authn11.base64;

import jakarta.persistence.Entity;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.springframework.data.jpa.repository.JpaRepository;

@Entity
class Base64RefreshTokenEntity {
    String token;

    Base64RefreshTokenEntity(String token) {
        this.token = token;
    }
}

interface Base64RefreshTokenRepository extends JpaRepository<Base64RefreshTokenEntity, Long> {
    <S extends Base64RefreshTokenEntity> S save(S entity);
}

class Base64Positive {
    Base64RefreshTokenRepository repository;

    void store(String refreshToken) {
        String encoded = Base64.getEncoder().encodeToString(
                refreshToken.getBytes(StandardCharsets.UTF_8));
        repository.save(new Base64RefreshTokenEntity(encoded));
    }
}
