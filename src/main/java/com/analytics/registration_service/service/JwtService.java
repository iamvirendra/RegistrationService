package com.analytics.registration_service.service;

import com.analytics.registration_service.entity.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Slf4j
@Service
public class JwtService {
    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.access-token-expiration}")
    private long accessTokenExpiration;

    private String buildToken(Map<String, Object> extraClaims, String subject, long expiration){
        return Jwts.builder()
                .claims(extraClaims)
                .subject(subject)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey())
                .compact();
    }

    public String generateAccessToken(User user){
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", user.getRole());
        claims.put("tokenVersion", user.getTokenVersion());
        claims.put("firstName", user.getFirstName());
        return buildToken(claims, user.getEmail(), accessTokenExpiration);
    }

    private SecretKey getSigningKey(){
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean isTokenValid(String token, User user){
        try{
            final String email = extractEmail(token);
            final Integer tokenVersion = extractTokenVersion(token);

            return email.equals(user.getEmail()) && !isTokenExpired(token) && tokenVersion != null && tokenVersion.equals(user.getTokenVersion());
        } catch (ExpiredJwtException e) {
            log.warn("JWT token is expiredP: {}", e.getMessage());
            return false;
        } catch (MalformedJwtException e) {
            log.warn("JWT token is malformed: {}", e.getMessage());
            return false;
        } catch (UnsupportedJwtException e) {
            log.warn("Jwt token is unsupported: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.warn("JWT token validation failed: {}", e.getMessage());
            return false;
        }
    }

    public String extractEmail(String token){
        return extractClaim(token, Claims::getSubject);
    }

    public Integer extractTokenVersion(String token){
        return extractClaim(token,
                claims -> claims.get("tokenVersion", Integer.class));
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

}
