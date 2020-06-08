package com.github.ricardobaumann.jwtauth;

import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.DefaultClock;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.util.Base64;

@EnableConfigurationProperties(JwtProperties.class)
public class JwtBeansConfiguration {

    private final JwtProperties jwtProperties;
    private final String base64EncodedSecret;

    public JwtBeansConfiguration(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        base64EncodedSecret = Base64.getEncoder().encodeToString(jwtProperties.getSecretKey().getBytes());
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtFilterConfigurer jwtConfigurer() {
        return new JwtFilterConfigurer(jwtTokenService());
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtTokenService jwtTokenService() {
        return new JwtTokenService(jwtProperties.getValidityInMillis(),
                jwtBuilder(),
                jwtParserBuilder(),
                clock());
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtBuilder jwtBuilder() {
        return Jwts.builder().signWith(Keys.hmacShaKeyFor(base64EncodedSecret.getBytes()), SignatureAlgorithm.HS256);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtParser jwtParserBuilder() {
        return Jwts.parserBuilder()
                .setClock(clock())
                .setSigningKey(Keys.hmacShaKeyFor(base64EncodedSecret.getBytes()))
                .build();
    }

    @Bean
    @ConditionalOnMissingBean
    public Clock clock() {
        return DefaultClock.INSTANCE;
    }
}

