package com.jberdeja.idm_authenticator.controller;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import com.jberdeja.idm_authenticator.entityes.JWTAuthenticateRequest;
import com.jberdeja.idm_authenticator.entityes.JWTResponse;
import com.jberdeja.idm_authenticator.service.AuthService;
import com.jberdeja.idm_authenticator.service.JwtService;

import io.jsonwebtoken.Claims;

@RestController
public class AuthController {
    @Autowired
    private AuthService authService;
    
    @Autowired
    private JwtService jwtService;
    
    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(@RequestBody JWTAuthenticateRequest request){
        String token = authService.executeAuthentication(request);
        return ResponseEntity.ok(new JWTResponse(token));
    }

    @GetMapping("/get-all-clams/{jwt}")
    public ResponseEntity<Claims> getAllClaims(@PathVariable String jwt){
        Claims claims = jwtService.getAllClaims(jwt);
        return ResponseEntity.ok(claims);
    }
}
