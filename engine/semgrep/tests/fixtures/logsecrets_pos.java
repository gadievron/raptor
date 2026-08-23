class LogSecretsPos {
    void f(org.slf4j.Logger log, String token, String key) {
        log.error("token=" + token);
        log.info("api_key: {}", key);
    }
}
