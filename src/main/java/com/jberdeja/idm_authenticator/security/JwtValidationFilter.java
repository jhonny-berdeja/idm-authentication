package com.jberdeja.idm_authenticator.security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.jberdeja.idm_authenticator.service.AuthService;
import com.jberdeja.idm_authenticator.service.JwtService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtValidationFilter extends OncePerRequestFilter{

    private static final String ROUTE_AUTHENTICATION = "/authenticate"; // Ruta pública

    @Autowired
    private JwtService jwtService;
    @Autowired
    private AuthService authService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (isNotPublicRoute(request)) filter(request);

        filterChain.doFilter(request, response);
    }

    private void filter(HttpServletRequest request){
        String token = jwtService.obtainTokenOfHttpServletRequest(request); 
         if (jwtService.isTokenValid(token)) {
             Authentication authenticationFromToken = authService.getAuthenticationFromToken(token);
             saveAuthenticationOnlyForRequestThreadContext(authenticationFromToken);
         }
    }

    private void saveAuthenticationOnlyForRequestThreadContext(Authentication authenticationFromToken){
        SecurityContextHolder.getContext().setAuthentication(authenticationFromToken);
    }

    private boolean isNotPublicRoute(HttpServletRequest request){
        return !isPublicRoute(request);
    }

    private boolean isPublicRoute(HttpServletRequest request) {
        return request.getRequestURI().equalsIgnoreCase(ROUTE_AUTHENTICATION);
    }
}
