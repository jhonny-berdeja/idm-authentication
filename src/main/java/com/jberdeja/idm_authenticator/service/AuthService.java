package com.jberdeja.idm_authenticator.service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Service;
import com.jberdeja.idm_authenticator.entityes.JWTAuthenticateRequest;

@Service
public class AuthService {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private InMemoryUserDetailsManager jwtUserDetailService;
    @Autowired
    private JwtService jwtService;

    public String executeAuthentication(JWTAuthenticateRequest request){
        authenticate(request);
        return obtainToken(request);
    }
    private void authenticate(JWTAuthenticateRequest request){
        try {
            authenticationManager.authenticate( buildUsernamePasswordAuthenticationToken(request));
        } catch (BadCredentialsException | DisabledException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    private UsernamePasswordAuthenticationToken buildUsernamePasswordAuthenticationToken(JWTAuthenticateRequest request){
        return new UsernamePasswordAuthenticationToken( request.getUsername(), request.getPassword());
    }

    private String obtainToken(JWTAuthenticateRequest request){
        var userDetails = jwtUserDetailService.loadUserByUsername(request.getUsername());
        return jwtService.generateToken(userDetails);
    }
}
