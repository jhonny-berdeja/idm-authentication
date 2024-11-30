package com.jberdeja.idm_authenticator.entityes;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class JWTAuthenticateRequest {
    private String username;
    private String password;
}
