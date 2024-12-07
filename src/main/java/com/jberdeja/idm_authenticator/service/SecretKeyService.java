package com.jberdeja.idm_authenticator.service;

import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.security.Keys;

@Service
public class SecretKeyService {

    @Value("${idm.jwt-secret}")
    private String jwtSecret;

    public SecretKey obtainSecretKey(){
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }
}
