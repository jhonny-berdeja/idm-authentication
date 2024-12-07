package com.jberdeja.idm_authenticator.controller;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
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
    public ResponseEntity<?> authenticate(@Validated @RequestBody JWTAuthenticateRequest request){
        try{
            JWTResponse response = authService.authenticate(request);
            return ResponseEntity.ok(response);
        }catch(Exception e){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    @GetMapping("/get-all-clams/{jwt}")
    public ResponseEntity<?> getAllClaims(@PathVariable String jwt){
        try{
            Claims claims = jwtService.getAllClaims(jwt);
            return ResponseEntity.ok(claims);
        }catch(Exception e){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }        
    }
}
