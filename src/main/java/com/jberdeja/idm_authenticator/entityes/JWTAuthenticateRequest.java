package com.jberdeja.idm_authenticator.entityes;

import lombok.Data;

@Data
public class JWTAuthenticateRequest {
    private String username;
    private String password;
}
