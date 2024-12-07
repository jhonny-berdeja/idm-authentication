package com.jberdeja.idm_authenticator.entityes;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class JWTAuthenticateRequest {
    @NotNull
    private String username;
    @NotNull
    private String password;
}
