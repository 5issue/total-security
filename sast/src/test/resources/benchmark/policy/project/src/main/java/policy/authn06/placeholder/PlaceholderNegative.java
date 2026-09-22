package policy.authn06.placeholder;

class PlaceholderNegative {
    String signingSecret = "${policy.jwt.secret}";
}
