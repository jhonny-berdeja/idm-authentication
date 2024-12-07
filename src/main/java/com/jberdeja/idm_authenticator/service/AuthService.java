package com.jberdeja.idm_authenticator.service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;
import com.jberdeja.idm_authenticator.entityes.JWTAuthenticateRequest;
import com.jberdeja.idm_authenticator.entityes.JWTResponse;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Service
public class AuthService {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserIDMDetailsService userIDMDetailsService;
    @Autowired
    private JwtService jwtService;

    public JWTResponse authenticate(JWTAuthenticateRequest request){
        log.info("starting authentication");
        authenticateWhitCredentials(request);
        String jwt = generateToken(request);
        log.info("finalized authentication ok");
        return new JWTResponse(jwt);
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

    private String generateToken(JWTAuthenticateRequest request){
        var userDetails = userIDMDetailsService.loadUserByUsername(request.getUsername());
        return jwtService.generateToken(userDetails);
    }
}
