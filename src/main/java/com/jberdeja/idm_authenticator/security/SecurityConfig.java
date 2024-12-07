package com.jberdeja.idm_authenticator.security;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfig {
    private static final String ALL = "*";
    private static final String POST = "POST";
    private static final String GET = "GET";
    private static final String ROUTE_AUTHENTICATION = "/authenticate";
    private static final String ROUTE_GET_ALL_CLAIMS = "/get-all-clams/**";

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, JwtValidationFilter jwtValidationFilter) throws Exception {
        http.addFilterBefore(jwtValidationFilter, UsernamePasswordAuthenticationFilter.class);
        http.authorizeHttpRequests(auth -> authorizeHttpRequestsConfigurer(auth));
        http.csrf(csrf -> csrfConfiguration(csrf));
        http.cors(cors -> corsConfigurationSource(cors));
        
        return http.build();
    }

    @SuppressWarnings("deprecation")
    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    private void csrfConfiguration(CsrfConfigurer<HttpSecurity> csrfCustomizer) {
        csrfCustomizer.ignoringRequestMatchers(ROUTE_AUTHENTICATION);
    }

    @SuppressWarnings("rawtypes")
    private AuthorizationManagerRequestMatcherRegistry authorizeHttpRequestsConfigurer( 
                            AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry auth) {
        auth.requestMatchers(ROUTE_AUTHENTICATION).permitAll();
        auth.requestMatchers(ROUTE_GET_ALL_CLAIMS).authenticated();
        return auth;
    }

    CorsConfigurationSource corsConfigurationSource(CorsConfigurer<HttpSecurity> httpSecurity){
        CorsConfiguration postConfig = corsConfigurationForPost();
        CorsConfiguration getConfig = corsConfigurationForGet();
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration(ROUTE_AUTHENTICATION, postConfig);
        source.registerCorsConfiguration(ROUTE_GET_ALL_CLAIMS, getConfig);
        httpSecurity.configurationSource(source);
        return source;
    }

    private CorsConfiguration corsConfigurationForPost(){
        CorsConfiguration postConfig = new CorsConfiguration();
        postConfig.setAllowedOrigins(List.of(ALL));
        postConfig.setAllowedMethods(List.of(POST));
        postConfig.setAllowedHeaders(List.of(ALL));//Falta limitar los header
        return postConfig;
    }    

    private CorsConfiguration corsConfigurationForGet(){
        CorsConfiguration getConfig = new CorsConfiguration();
        getConfig.setAllowedOrigins(List.of(ALL));//Cuando configuremos el DNS de los containers el origen sera unico
        getConfig.setAllowedMethods(List.of(GET));
        getConfig.setAllowedHeaders(List.of(ALL));//Falta limitar los header
        return getConfig;
    }
}