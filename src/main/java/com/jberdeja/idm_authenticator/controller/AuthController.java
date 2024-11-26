package com.jberdeja.idm_authenticator.controller;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import com.jberdeja.idm_authenticator.entityes.JWTRequest;
import com.jberdeja.idm_authenticator.entityes.JWTResponse;
import com.jberdeja.idm_authenticator.service.AuthService;

@RestController
public class AuthController {
    @Autowired
    private AuthService authService;
    
    @PostMapping("/authenticate")
    public ResponseEntity<?> postToken(@RequestBody JWTRequest request){
        final String token = authService.executeAuthentication(request);
        return ResponseEntity.ok(new JWTResponse(token));
    }
}
