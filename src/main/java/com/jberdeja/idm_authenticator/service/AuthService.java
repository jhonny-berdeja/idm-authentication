package com.jberdeja.idm_authenticator.service;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import com.jberdeja.idm_authenticator.entityes.JWTAuthenticateRequest;
import com.jberdeja.idm_authenticator.entityes.JWTResponse;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Service
public class AuthService {
    private static final String ROLES = "ROLES";
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserIDMDetailsService userIDMDetailsService;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private ClaimsService claimsService;

    public JWTResponse authenticateUser(JWTAuthenticateRequest request){
        log.info("starting authentication of user");
        authenticateWhitCredentials(request);
        String jwt = jwtService.generateTokenWhitUserOfDatabase(request.getUsername());
        log.info("finalized authentication of user ok");
        return new JWTResponse(jwt);
    }

    public Authentication getAuthenticationFromToken(String token) {
        Claims claimsFromTokem = claimsService.getClaimsFromToken(token);
        String usernameFromToken = claimsFromTokem.getSubject();
        List<GrantedAuthority> authorities = obtainListOfGrantedAuthoritiesFromToken(claimsFromTokem);
        return new UsernamePasswordAuthenticationToken(
            usernameFromToken, null, authorities
        );
    }

    @SuppressWarnings("unchecked")
    private List<GrantedAuthority> obtainListOfGrantedAuthoritiesFromToken(Claims claimsFromToken){

        List<String> roleFromClaims = claimsService.obtainRolesFromClaims(claimsFromToken);
        
        if(Optional.ofNullable(roleFromClaims).isEmpty()){
            log.error("The claims role list is empty");
            throw new IllegalArgumentException("The claims role list is empty");
        }

        return roleFromClaims.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

    }

    private void authenticateWhitCredentials(JWTAuthenticateRequest request){
        try {
            authenticationManager.authenticate( buildUsernamePasswordAuthenticationToken(request));
        } catch (Exception e) {
            log.error("Error authenticating with credentials", e);
            throw new RuntimeException(e.getMessage());
        }
    }

    private UsernamePasswordAuthenticationToken buildUsernamePasswordAuthenticationToken(JWTAuthenticateRequest request){
        return new UsernamePasswordAuthenticationToken( request.getUsername(), request.getPassword());
    }
}
