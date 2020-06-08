package com.github.ricardobaumann.jwtauth;

import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

public class JwtDefaultSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final JwtFilterConfigurer jwtFilterConfigurer;

    public JwtDefaultSecurityConfiguration(JwtFilterConfigurer jwtFilterConfigurer) {
        this.jwtFilterConfigurer = jwtFilterConfigurer;
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic().disable()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .anyRequest().authenticated()
                .and().apply(jwtFilterConfigurer);
    }
}
