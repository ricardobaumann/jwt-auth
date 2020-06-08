package com.github.ricardobaumann.jwtauth;

import io.jsonwebtoken.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.List;
import java.util.Optional;

public class JwtTokenService {

    private final Long tokenValidityInMillis;
    private final JwtBuilder jwtBuilder;
    private final JwtParser jwtParser;
    private final Clock clock;

    public JwtTokenService(Long tokenValidityInMillis,
                           JwtBuilder jwtBuilder,
                           JwtParser jwtParser,
                           Clock clock) {
        this.tokenValidityInMillis = tokenValidityInMillis;
        this.jwtBuilder = jwtBuilder;
        this.jwtParser = jwtParser;
        this.clock = clock;
    }

    public String createTokenFor(String username, List<String> roles) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("roles", roles);
        Date now = clock.now();
        return jwtBuilder
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + tokenValidityInMillis))
                .compact();
    }

    private Optional<String> resolveTokenFrom(HttpServletRequest request) {

        return Optional.ofNullable(request.getHeader("Authorization"))
                .filter(authHeader -> authHeader.startsWith("Bearer "))
                .map(bearerToken -> bearerToken.substring(7));
    }

    public Optional<Authentication> resolveAuthFrom(HttpServletRequest request) {
        return resolveTokenFrom(request)
                .map(this::parseClaims)
                .map(Jwt::getBody)
                .flatMap(this::toAuthentication);
    }

    private Optional<Authentication> toAuthentication(Claims claims) {
        return Optional.ofNullable(claims.get("roles", List.class))
                .map(roles -> new CustomUserDetails(claims.getSubject(), roles))
                .map(customUserDetails -> new UsernamePasswordAuthenticationToken(customUserDetails, "", customUserDetails.getAuthorities()));
    }


    private Jws<Claims> parseClaims(String token) {
        return jwtParser.parseClaimsJws(token);
    }
}
