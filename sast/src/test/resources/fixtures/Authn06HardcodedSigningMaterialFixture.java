package fixtures.authn;

import org.springframework.beans.factory.annotation.Value;

class JwtConfig {
    private static final String JWT_SECRET = "a-real-looking-signing-secret-value";
    private String signingSecret = "production-signing-material-2026";
    private String secretKey = "literal-secret";
    private String jwtSecretOne = "distinct-signing-secret-one";
    private String jwtSecretTwo = "distinct-signing-secret-two";
    private String jwtSecretWithExampleSubstring =
            "prod-examplecorp-signing-secret-2026";
    private String jwtSecretWithDummySubstring =
            "prod-dummycorp-signing-secret-2026";

    @Value("${jwt.secret}")
    private String injectedSecret;

    void localAndAssignment() {
        String signingKey = "local-signing-material";
        String jwtSecret;
        jwtSecret = "later-signing-material";
    }

    void externalSources(Environment environment, KmsClient kmsClient) {
        String jwtSecretFromEnvironment = System.getenv("JWT_SECRET");
        String signingSecretFromProperty = environment.getProperty("jwt.secret");
        String signingKeyFromKms = kmsClient.decrypt("alias/jwt-signing-key");
    }

    void safeLiterals() {
        String message = "failed to load secret";
        String signingAlgorithm = "HS256";
        String signingKeyAlias = "alias/jwt-signing-key";
        String jwtSecretPlaceholder = "example-signing-secret";
        String jwtSecretChangeMe = "change-me";
        String jwtSecretProperty = "${jwt.secret}";
        String jwtSecretEmpty = "";
    }
}

class PemConfig {
    private String privateKey = """
            -----BEGIN PRIVATE KEY-----
            base64-private-material
            -----END PRIVATE KEY-----
            """;

    private String rsaPrivateKey = """
            -----BEGIN RSA PRIVATE KEY-----
            base64-rsa-private-material
            -----END RSA PRIVATE KEY-----
            """;

    private String ecPrivateKey = """
            -----BEGIN EC PRIVATE KEY-----
            base64-ec-private-material
            -----END EC PRIVATE KEY-----
            """;

    private String publicKey = """
            -----BEGIN PUBLIC KEY-----
            base64-public-material
            -----END PUBLIC KEY-----
            """;

    private String certificate = """
            -----BEGIN CERTIFICATE-----
            base64-certificate-material
            -----END CERTIFICATE-----
            """;

    private String examplePrivateKey = """
            -----BEGIN PRIVATE KEY-----
            example-placeholder
            -----END PRIVATE KEY-----
            """;

    private String jwtSecretIncompleteBegin = "-----BEGIN PRIVATE KEY-----";
    private String jwtSecretIncompleteEnd = "-----END PRIVATE KEY-----";
    private String jwtSigningSecretIncomplete = "-----BEGIN PRIVATE KEY-----";
    private String jwtSecretMismatchedPem = """
            -----BEGIN RSA PRIVATE KEY-----
            body
            -----END PRIVATE KEY-----
            """;

    private String jwtPrivateKeyReverseOrder = """
            -----END PRIVATE KEY-----
            payload
            -----BEGIN PRIVATE KEY-----
            """;

    private String jwtSigningSecretReverseOrder = """
            -----END PRIVATE KEY-----
            payload
            -----BEGIN PRIVATE KEY-----
            """;

    private String rsaPrivateKeyReverseOrder = """
            -----END RSA PRIVATE KEY-----
            payload
            -----BEGIN RSA PRIVATE KEY-----
            """;
}

interface Environment {
    String getProperty(String name);
}

interface KmsClient {
    String decrypt(String keyAlias);
}
