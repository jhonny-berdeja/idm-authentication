package com.jberdeja.idm_authenticator.service;

import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class JwtService {
    private static final long JWT_TOKEN_VALIDATY = 5 * 60 * 60;
    private static final String ROLES = "ROLES";
    private static final boolean TRUE = true;
    private static final boolean FALSE = false;
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String AUTHORIZATION_HEADER_BEARER = "Bearer ";
    private static final String PREFIX_BEARER = "(?i)Bearer ";
    private static final String EMPTY = "";

    @Value("${idm.jwt-secret}")
    private String jwtSecret;

    @Autowired
    private UserIDMDetailsService userIDMDetailsService;

    @Autowired
    private ClaimsService claimsService;

    @Autowired
    private SecretKeyService secretKeyService;

    public boolean isTokenValid(String token) {
        try{
            Claims claimsFromTokem = claimsService.getClaimsFromToken(token);
            String usernameFromToken = claimsFromTokem.getSubject();
            validateUsernameFromToken(usernameFromToken);
            UserDetails userDetailsFromDatabase = obtainUserDetailsFromDatabase(usernameFromToken);
            String usernameFromDatabase = userDetailsFromDatabase.getUsername();
            validateAuthenticatedUserToken(usernameFromToken, usernameFromDatabase);
        return TRUE;
        }catch(Exception e){
            log.error("Error validating token", e);
            return FALSE;
        }
    }
 
    public String obtainTokenOfHttpServletRequest(HttpServletRequest request) {
        var requestTokenHeader = request.getHeader(AUTHORIZATION_HEADER);
        if(isNotValidTokenHeader(requestTokenHeader))
            throw new IllegalArgumentException("The token header is not valid");
        return requestTokenHeader.replaceFirst(PREFIX_BEARER, EMPTY);

    }

    public String generateTokenWhitUserOfDatabase(String username){
        try{
            var userDetails = userIDMDetailsService.loadUserByUsername(username);
            final Map<String, Object> claims = Collections.singletonMap(ROLES, userDetails.getAuthorities().toString());
            return buildToken(claims, userDetails.getUsername());
        }catch(Exception e){
            log.error("Error generating token", e);
            throw new RuntimeException(e);
        }
    }

    private boolean isNotValidTokenHeader(String requestTokenHeader){
        return !isValidTokenHeader(requestTokenHeader);
    }
    private boolean isValidTokenHeader(String requestTokenHeader){
        return Objects.nonNull(requestTokenHeader) 
                    && requestTokenHeader.startsWith(AUTHORIZATION_HEADER_BEARER);
    }

    private void validateAuthenticatedUserToken(String usernameFromToken, String usernameFromDatabase){
        if(isNotTokenOwnedByAuthenticatedUser(usernameFromToken, usernameFromDatabase)){
            log.error("Error the token is not from the authenticated user");
            throw new IllegalArgumentException("Error the token is not from the authenticated user");
        }
    }

    private boolean isNotTokenOwnedByAuthenticatedUser(String usernameFromToken, String usernameFromDatabase){
        return !isTokenOwnedByAuthenticatedUser(usernameFromToken, usernameFromDatabase);
    }

    private boolean isTokenOwnedByAuthenticatedUser(String usernameFromToken, String usernameFromDatabase){
        return usernameFromToken.equalsIgnoreCase(usernameFromDatabase);
    }

    private UserDetails obtainUserDetailsFromDatabase(String username){
        return userIDMDetailsService.loadUserByUsername(username);
    }

    private void validateUsernameFromToken(String username){
        if(isNotValidUsername(username)){
            log.error("The token username is not valid");
            throw new IllegalArgumentException("TThe token username is not valid");
        }
    }

    private boolean isNotValidUsername(String username){
        return !isValidUsername(username);
    }

    private boolean isValidUsername(String username){
        return Objects.nonNull(username) && isNotBlackUsername(username);
    }

    private boolean isNotBlackUsername(String username){
        return !username.isBlank();
    }

    private String buildToken(Map<String, Object> claims, String subject){
        final var key = secretKeyService.obtainSecretKey();
        return Jwts.builder()
        .setClaims(claims)
        .setSubject(subject)
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDATY * 1000))
        .signWith(key)
        .compact();

    }
}
