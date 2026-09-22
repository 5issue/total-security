package policy.authn06.runtime;

class RuntimeSecretNegative {
    String jwtSecret = System.getenv("POLICY_JWT_SECRET");
}
