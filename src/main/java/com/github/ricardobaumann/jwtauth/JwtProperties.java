package com.github.ricardobaumann.jwtauth;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    private String secretKey;
    private Long validityInMillis = Long.MAX_VALUE;

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public Long getValidityInMillis() {
        return validityInMillis;
    }

    public void setValidityInMillis(Long validityInMillis) {
        this.validityInMillis = validityInMillis;
    }
}
