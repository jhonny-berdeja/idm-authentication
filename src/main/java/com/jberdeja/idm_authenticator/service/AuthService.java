package com.jberdeja.idm_authenticator.service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Service;
import com.jberdeja.idm_authenticator.entityes.JWTRequest;

@Service
public class AuthService {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private InMemoryUserDetailsManager jwtUserDetailService;
    @Autowired
    private JwtService jwtService;

    public String executeAuthentication(JWTRequest request){
        this.authenticate(request);
        return this.obtainToken(request);
    }
    private void authenticate(JWTRequest request){
        try {
            this.authenticationManager.authenticate( buildUsernamePasswordAuthenticationToken(request));
        } catch (BadCredentialsException | DisabledException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    private UsernamePasswordAuthenticationToken buildUsernamePasswordAuthenticationToken(JWTRequest request){
        return new UsernamePasswordAuthenticationToken( request.getUsername(), request.getPassword());
    }

    private String obtainToken(JWTRequest request){
        var userDetails = this.jwtUserDetailService.loadUserByUsername(request.getUsername());
        return this.jwtService.generateToken(userDetails);
    }
}
