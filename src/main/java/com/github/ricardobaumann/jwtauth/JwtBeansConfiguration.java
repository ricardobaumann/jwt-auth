package com.github.ricardobaumann.jwtauth;

import io.jsonwebtoken.Clock;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.DefaultClock;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@EnableConfigurationProperties(JwtProperties.class)
public class JwtBeansConfiguration {

    private final JwtProperties jwtProperties;

    public JwtBeansConfiguration(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtConfigurer jwtConfigurer() {
        return new JwtConfigurer(jwtTokenService());
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtTokenService jwtTokenService() {
        return new JwtTokenService(jwtProperties, jwtBuilder(), jwtParserBuilder(), clock());
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtBuilder jwtBuilder() {
        return Jwts.builder();
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtParserBuilder jwtParserBuilder() {
        return Jwts.parserBuilder().setClock(clock());
    }

    @Bean
    @ConditionalOnMissingBean
    public Clock clock() {
        return DefaultClock.INSTANCE;
    }
}

