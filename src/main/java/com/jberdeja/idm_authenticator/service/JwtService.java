package com.jberdeja.idm_authenticator.service;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import javax.crypto.SecretKey;
import io.jsonwebtoken.SignatureException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
    private static final long JWT_TOKEN_VALIDATY = 5 * 60 * 60;
    private static final String JWT_SECRET = "ClientSecret1ClientSecret2ClientSecret3XXX";
    private static final String ROLES = "ROLES";

    public String generateToken(UserDetails userDetails){
        final Map<String, Object> claims = Collections.singletonMap(ROLES, userDetails.getAuthorities().toString());
        return getToken(claims, userDetails.getUsername());
    }

    @SuppressWarnings("deprecation")
    public Claims getAllClaims(String token) {
        try {
            return getAllClaimsFromToken(token);
        } catch (SignatureException e) {
            throw new RuntimeException("Token inválido: firma no coincide");
        } catch (Exception e) {
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
        return Keys.hmacShaKeyFor(JWT_SECRET.getBytes(StandardCharsets.UTF_8));
    }
}
