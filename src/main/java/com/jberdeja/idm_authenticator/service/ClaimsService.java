package com.jberdeja.idm_authenticator.service;

import java.util.List;
import java.util.Objects;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class ClaimsService {
    private static final String ROLES = "ROLES";
    @Value("${idm.jwt-secret}")
    private String jwtSecret;

    @Autowired
    private SecretKeyService secretKeyService;

    @SuppressWarnings("deprecation")
    public Claims getClaimsFromToken(String token){
        try {
            if(Objects.isNull(token)) throw new RuntimeException("Token is null");
            var key = secretKeyService.obtainSecretKey();
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (SignatureException e) {
            log.error("The token signature is invalid.", e);
            throw new IllegalArgumentException("The token signature is invalid.", e);
        } catch (ExpiredJwtException e) {
            log.error("The token has expired.", e);
            throw new IllegalArgumentException("The token has expired.", e);
        } catch (MalformedJwtException e) {
            log.error("The token is malformed.", e);
            throw new IllegalArgumentException("The token is malformed.", e);
        } catch (Exception e) {
            log.error("Error processing token.", e);
            throw new IllegalArgumentException("Error processing token.", e);
        }
    }

    public List<String> obtainRolesFromClaims(Claims claimsFromToken){
        try {
            String rolesFromClaims = claimsFromToken.get(ROLES, String.class);
            String[] roles = rolesFromClaims.replace("[", "").replace("]", "").split(",");
            return List.of(roles);
        } catch (Exception e) {
            log.error("error getting Claims roles");
            throw new IllegalArgumentException("error getting Claims roles", e);
        }
    }
}
