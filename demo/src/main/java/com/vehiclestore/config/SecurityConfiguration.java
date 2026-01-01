package com.vehiclestore.config;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.util.Base64;
import com.vehiclestore.util.SecurityUtil;

// Main Spring Security configuration class
// This class configures how authentication and authorization work in the application
@Configuration
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfiguration {

    @Value("${vehcilestore.jwt.base64-secret}")
    private String jwtKey;

    // Bean to encode passwords using BCrypt algorithm
    // BCrypt is a one-way hash function - cannot decrypt back to original password
    // Used when: 1) Creating user (encode password before save to DB)
    // 2) Login (compare input password with hashed password in DB)
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // DaoAuthenticationProvider - The bridge between Spring Security and your
    // custom UserDetailsService
    // This tells Spring Security:
    // 1) WHERE to find user info -> UserDetailsService (our UserDetailCustom class)
    // 2) HOW to compare passwords -> PasswordEncoder (BCrypt)
    // Authentication flow: Login request -> AuthenticationManager ->
    // DaoAuthenticationProvider
    // -> UserDetailsService.loadUserByUsername() -> Compare password
    @Bean
    public DaoAuthenticationProvider authProvider(
            PasswordEncoder passwordEncoder,
            UserDetailsService userDetailsService) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService); // Use our custom UserDetailCustom
        authProvider.setPasswordEncoder(passwordEncoder); // Use BCrypt to compare passwords
        // authProvider.setHideUserNotFoundExceptions(false); // If true: show "User not
        // found" error
        return authProvider;
    }

    // SecurityFilterChain - Configure HTTP security rules
    // Defines which endpoints are public/protected and how requests are handled
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(c -> c.disable()) // Disable CSRF for REST API (stateless, no cookies)
                .authorizeHttpRequests(
                        authz -> authz
                                .requestMatchers("/").permitAll() // "/" is public
                                // .anyRequest().authenticated()) // All other requests need authentication
                                .anyRequest().permitAll()) // DEVELOPMENT ONLY: allow all requests
                .formLogin(f -> f.disable()) // Disable default login form (we use custom /login API)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // No
                                                                                                               // session,
                                                                                                               // each
                                                                                                               // request
                                                                                                               // must
                                                                                                               // authenticate

        return http.build();
    }

    @Bean
    public JwtEncoder jwtEncoder() {
        return new NimbusJwtEncoder(new ImmutableSecret<>(getSecretKey()));
    }

    private SecretKey getSecretKey() {
        byte[] keyBytes = Base64.from(jwtKey).decode();
        return new SecretKeySpec(keyBytes, 0, keyBytes.length, SecurityUtil.JWT_ALGORITHM.getName());
    }

    @Bean
    public MvcRequestMatcher.Builder mvc(HandlerMappingIntrospector introspector) {
        return new MvcRequestMatcher.Builder(introspector);
    }
}
