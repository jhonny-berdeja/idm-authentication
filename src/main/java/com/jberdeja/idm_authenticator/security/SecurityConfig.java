package com.jberdeja.idm_authenticator.security;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfig {
    private static final String ALL = "*";
    private static final String POST = "POST";
    private static final String GET = "GET";
    private static final String ROUTE_AUTHENTICATION = "authenticate";
    private static final String ROUTE_GET_ALL_CLAIMS = "get-all-clams";

    @Bean
    SecurityFilterChain securityFilterChaim( HttpSecurity http ) throws Exception{
        http.cors(cors-> corsConfigurationSource());
        http.csrf(csrf-> csrfConfiguration(csrf));
        return http.build();
    }

    @Bean
    InMemoryUserDetailsManager inMemoryUserDetailsManager(){
        var admin = User.withUsername("admin")
        .password("to_be_encoded")
        .authorities("CARDS")
        .build();

        var user = User.withUsername("user")
        .password("to_be_encoded")
        .authorities("CARDS")
        .build();

        return new InMemoryUserDetailsManager(admin, user);
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    } 

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception{
        return configuration.getAuthenticationManager();
    }

    private void csrfConfiguration(CsrfConfigurer<HttpSecurity> csrfCustomizer){
        csrfCustomizer.ignoringRequestMatchers(ROUTE_AUTHENTICATION);
    }

    private CorsConfigurationSource corsConfigurationSource(){
        var configPost = buildCorsConfigurationForPost();
        var configGet = buildCorsConfigurationForGet();
        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration(ROUTE_AUTHENTICATION, configPost);
        source.registerCorsConfiguration(ROUTE_GET_ALL_CLAIMS, configGet);
        return source;
    }

    private CorsConfiguration buildCorsConfigurationForPost(){
        var config = new CorsConfiguration();
        config.setAllowedOrigins(List.of(ALL));
        config.setAllowedMethods(List.of(POST, GET));
        config.setAllowedHeaders(List.of(ALL));
        return config;
    }

    private CorsConfiguration buildCorsConfigurationForGet(){
        var config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:8081")); // Solo para este origen
        config.setAllowedMethods(List.of("GET"));
        config.setAllowedHeaders(List.of("*"));
        return config;
    }
}
