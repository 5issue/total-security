package fixtures;

class HardcodedCredentialFixture {
    private String password = "FieldSecret123!";

    void localPassword() {
        String password = "LocalSecret123!";
    }

    void passwd() {
        String passwd = "PasswdSecret123!";
    }

    void pwd() {
        String pwd = "PwdSecret123!";
    }

    void secretKey() {
        String secretKey = "SecretKey123!";
    }

    void clientSecret() {
        String clientSecret = "ClientSecret123!";
    }

    void apiKey() {
        String apiKey = "ApiKey123!";
    }

    void apiSnakeCase() {
        String api_key = "ApiSnakeKey123!";
    }

    void accessToken() {
        String accessToken = "AccessToken123!";
    }

    void authToken() {
        String authToken = "AuthToken123!";
    }

    void laterAssignment() {
        String password;
        password = "LaterSecret123!";
    }

    void twoAssignments() {
        String token;
        token = "FirstToken123!";
        token = "SecondToken123!";
    }

    void passwordFromCall() {
        String password = getPassword();
    }

    void apiKeyFromEnvironment() {
        String apiKey = System.getenv("API_KEY");
    }

    void tokenFromRequest(Request request) {
        String token = request.getParameter("token");
    }

    void secretFromConfig(Config config) {
        String secret = config.getSecret();
    }

    void normalLiteral() {
        String displayName = "ordinary-value";
    }

    void emptyPassword() {
        String password = "";
    }

    void whitespacePassword() {
        String password = "  \t  ";
    }

    void vaguelyRelatedNames() {
        String tokenCount = "3";
        String passwordEnabled = "true";
        String secretary = "name";
        String apiKeyEnabled = "true";
    }

    void customMethodReturn() {
        String privateKey = customValue();
    }

    private String getPassword() {
        return "runtime";
    }

    private String customValue() {
        return "runtime";
    }

    interface Request {
        String getParameter(String name);
    }

    interface Config {
        String getSecret();
    }
}
