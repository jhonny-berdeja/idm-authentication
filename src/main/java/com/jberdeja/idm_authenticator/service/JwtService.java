package com.jberdeja.idm_authenticator.service;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import javax.crypto.SecretKey;
import io.jsonwebtoken.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class JwtService {
    private static final long JWT_TOKEN_VALIDATY = 5 * 60 * 60;
    private static final String ROLES = "ROLES";
    @Value("${idm.jwt-secret}")
    private String jwtSecret;

    public String generateToken(UserDetails userDetails){
        try{
            final Map<String, Object> claims = Collections.singletonMap(ROLES, userDetails.getAuthorities().toString());
            return getToken(claims, userDetails.getUsername());
        }catch(Exception e){
            log.error("Error generating token", e);
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("deprecation")
    public Claims getAllClaims(String token) {
        try {
            if(Objects.isNull(token)) throw new Exception("Token is null");
            return getAllClaimsFromToken(token);
        } catch (SignatureException e) {
            log.error("invalid token signature", e);
            throw new RuntimeException("Invalid token, signature does not match");
        } catch (Exception e) {
            log.error("invalid token", e);
            throw new RuntimeException("Token inválido: " + e.getMessage());
        }
    }

    private Claims getAllClaimsFromToken(String token){
        var key = obtainSecretKey();
        return Jwts
        .parserBuilder()
        .setSigningKey(key)
        .build()
        .parseClaimsJws(token)
        .getBody();
    }

    private String getToken(Map<String, Object> claims, String subject){
        final var key = obtainSecretKey();
        return Jwts.builder()
        .setClaims(claims)
        .setSubject(subject)
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDATY * 1000))
        .signWith(key)
        .compact();

    }
    private SecretKey obtainSecretKey(){
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }
}
