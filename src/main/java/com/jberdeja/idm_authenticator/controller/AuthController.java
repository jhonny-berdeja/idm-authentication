package com.jberdeja.idm_authenticator.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.jberdeja.idm_authenticator.entityes.JWTRequest;
import com.jberdeja.idm_authenticator.entityes.JWTResponse;
import com.jberdeja.idm_authenticator.service.JwtService;

import lombok.AllArgsConstructor;

@RestController
@AllArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;

    private final InMemoryUserDetailsManager jwtUserDetailService;
    
    private final JwtService jwtService;
    //Hace la authenticación antes de generar el token
    @PostMapping("/authenticate")
    public ResponseEntity<?> postToken(@RequestBody JWTRequest request){

        this.authenticate(request);

        final var userDetails = this.jwtUserDetailService.loadUserByUsername(request.getUsername());

        final String token = this.jwtService.generateToken(userDetails);

        return ResponseEntity.ok(new JWTResponse(token));
    }

    private void authenticate(JWTRequest request){
        try {

            this.authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    request.getUsername(), 
                    request.getPassword()));

        } catch (BadCredentialsException | DisabledException e) {

            throw new RuntimeException(e.getMessage());

        }
    }


}
