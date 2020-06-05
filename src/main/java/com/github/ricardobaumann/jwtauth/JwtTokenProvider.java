package com.github.ricardobaumann.jwtauth;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;

public class JwtTokenProvider {

    private final String secretKey;

    public JwtTokenProvider(String secretKey) {
        this.secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    public String createTokenFor(String username, List<String> roles) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("roles", roles);
        Date now = new Date();
        //Date validity = new Date(now.getTime() + validityInMillis);
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                //.setExpiration(validity)
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()), SignatureAlgorithm.HS256)
                .compact();
    }

    private boolean isValid(Jws<Claims> claimsJws) {
        return Optional.ofNullable(claimsJws.getBody())
                .map(Claims::getExpiration)
                .filter(date -> date.before(new Date()))
                .isPresent();
    }

    private Optional<String> resolveTokenFrom(HttpServletRequest request) {

        return Optional.ofNullable(request.getHeader("Authorization"))
                .filter(authHeader -> authHeader.startsWith("Bearer "))
                .map(bearerToken -> bearerToken.substring(7));
    }

    public Optional<Authentication> resolveAuthFrom(HttpServletRequest request) {
        return resolveTokenFrom(request)
                .map(this::parseClaims)
                //.filter(this::isValid)
                .map(Jwt::getBody)
                .flatMap(this::toAuthentication);
    }

    private Optional<Authentication> toAuthentication(Claims claims) {
        return Optional.ofNullable(claims.get("roles", List.class))
                .map(roles -> new CustomUserDetails(claims.getSubject(), roles))
                .map(customUserDetails -> new UsernamePasswordAuthenticationToken(customUserDetails, "", customUserDetails.getAuthorities()));
    }


    private Jws<Claims> parseClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes())).build().parseClaimsJws(token);
    }
}
