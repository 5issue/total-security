package policy.authn11.nopersistence;

class NoPersistenceNegative {
    String respond(String refreshToken) {
        return "cookie=" + refreshToken;
    }
}
