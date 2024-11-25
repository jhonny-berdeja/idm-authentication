package com.jberdeja.idm_authenticator.entityes;

import lombok.Data;

@Data
public class JWTRequest {

    private String username;
    private String password;
}
