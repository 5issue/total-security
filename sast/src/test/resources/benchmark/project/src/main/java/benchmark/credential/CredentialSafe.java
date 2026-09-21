package benchmark.credential;

class CredentialSafe {
    private String password = System.getenv("BENCHMARK_PASSWORD");
    private String displayName = "example-user";
}
