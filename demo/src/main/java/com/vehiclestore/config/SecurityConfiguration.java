package com.vehiclestore.config;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.util.Base64;
import com.vehiclestore.util.SecurityUtil;

/**
 * =============================================================================
 * SPRING SECURITY CONFIGURATION CLASS
 * =============================================================================
 * This is the MAIN configuration class for Spring Security in this application.
 * 
 * KEY CONCEPTS:
 * -------------
 * 1. @Configuration: Marks this class as a Spring configuration class
 *    - Spring will scan this class and create all @Bean methods as Spring beans
 *    - These beans are singletons (created once, shared everywhere)
 * 
 * 2. @EnableMethodSecurity: Enables method-level security annotations
 *    - Allows using @Secured, @PreAuthorize, @PostAuthorize on controller methods
 *    - Example: @Secured("ROLE_ADMIN") on a method = only admins can access
 * 
 * AUTHENTICATION vs AUTHORIZATION:
 * --------------------------------
 * - Authentication = WHO are you? (verify identity via username/password)
 * - Authorization = WHAT can you do? (check permissions/roles)
 * 
 * FLOW OVERVIEW:
 * --------------
 * Request → SecurityFilterChain → JWT validation → Controller
 *                                   ↓
 *                           (if login) → AuthenticationProvider → UserDetailsService
 */
@Configuration
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfiguration {

    /**
     * JWT Secret Key loaded from application.properties
     * @Value annotation injects the property value into this field
     * This key is used for both:
     * - Signing JWT tokens (JwtEncoder)
     * - Verifying JWT tokens (JwtDecoder)
     */
    @Value("${vehcilestore.jwt.base64-secret}")
    private String jwtKey;

    /**
     * =========================================================================
     * PASSWORD ENCODER BEAN
     * =========================================================================
     * BCryptPasswordEncoder - Industry standard for password hashing
     * 
     * WHY BCrypt?
     * -----------
     * 1. One-way hash: Cannot decrypt back to original password
     * 2. Salt included: Same password = different hash each time
     * 3. Slow by design: Harder for attackers to brute-force
     * 
     * HOW IT WORKS:
     * -------------
     * Encoding: "myPassword" → "$2a$10$N9qo8uLOickgx2ZMRZoMy..."
     * Matching: Compare input password with stored hash (returns true/false)
     * 
     * USED IN:
     * --------
     * 1. UserService.handleCreateUser() - encode password before saving to DB
     * 2. DaoAuthenticationProvider - compare login password with DB hash
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * =========================================================================
     * DAO AUTHENTICATION PROVIDER BEAN
     * =========================================================================
     * The BRIDGE between Spring Security and YOUR custom user database
     * 
     * WHAT IT DOES:
     * -------------
     * 1. Receives login credentials (username/password)
     * 2. Calls UserDetailsService to load user from database
     * 3. Uses PasswordEncoder to compare passwords
     * 4. Returns authenticated user or throws exception
     * 
     * AUTHENTICATION FLOW:
     * --------------------
     * POST /login (username, password)
     *      ↓
     * AuthController.login()
     *      ↓
     * AuthenticationManager.authenticate()
     *      ↓
     * DaoAuthenticationProvider
     *      ↓
     * UserDetailsService.loadUserByUsername(username)  ← Find user in DB
     *      ↓
     * PasswordEncoder.matches(inputPassword, dbPassword)  ← Compare passwords
     *      ↓
     * Return Authentication object (success) or throw BadCredentialsException (fail)
     * 
     * @param passwordEncoder - BCrypt encoder for password comparison
     * @param userDetailsService - Our custom UserDetailCustom class
     */
    @Bean
    public DaoAuthenticationProvider authProvider(
            PasswordEncoder passwordEncoder,
            UserDetailsService userDetailsService) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        
        // Tell Spring Security WHERE to find user info
        // This connects to our UserDetailCustom.loadUserByUsername() method
        authProvider.setUserDetailsService(userDetailsService);
        
        // Tell Spring Security HOW to compare passwords
        // BCrypt will compare: input password vs hashed password in DB
        authProvider.setPasswordEncoder(passwordEncoder);
        
        // Optional: If uncommented, will show "User not found" instead of generic "Bad credentials"
        // authProvider.setHideUserNotFoundExceptions(false);
        
        return authProvider;
    }

    /**
     * =========================================================================
     * SECURITY FILTER CHAIN BEAN
     * =========================================================================
     * The CORE of Spring Security - defines ALL security rules for HTTP requests
     * 
     * WHAT IS A FILTER CHAIN?
     * -----------------------
     * Every HTTP request passes through a series of security filters:
     * Request → Filter1 → Filter2 → Filter3 → ... → Controller
     * 
     * Each filter can:
     * - Block the request (return 401/403)
     * - Modify the request
     * - Pass to next filter
     * 
     * KEY CONFIGURATIONS EXPLAINED:
     * -----------------------------
     * 1. csrf().disable()
     *    - CSRF = Cross-Site Request Forgery protection
     *    - Disabled for REST APIs (we use JWT tokens instead of cookies)
     *    - Enable for traditional web apps with forms/cookies
     * 
     * 2. authorizeHttpRequests()
     *    - Define which URLs are public vs protected
     *    - Order matters! First match wins
     * 
     * 3. oauth2ResourceServer().jwt()
     *    - Enable JWT token validation for protected endpoints
     *    - Every request must include: Authorization: Bearer <token>
     * 
     * 4. sessionManagement(STATELESS)
     *    - REST APIs are stateless (no server-side sessions)
     *    - Each request must authenticate itself (via JWT)
     *    - Better for scalability (no session storage needed)
     * 
     * REQUEST FLOW FOR PROTECTED ENDPOINT:
     * ------------------------------------
     * GET /users (with header: Authorization: Bearer eyJhbGc...)
     *      ↓
     * JwtAuthenticationFilter extracts token
     *      ↓
     * JwtDecoder validates token signature & expiration
     *      ↓
     * If valid → Continue to controller
     * If invalid → Return 401 Unauthorized
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // CSRF Protection - Disabled for stateless REST API
                // REST APIs use tokens (not cookies), so CSRF attack is not applicable
                .csrf(c -> c.disable())
                
                // URL Authorization Rules
                // Define which endpoints are public and which require authentication
                .authorizeHttpRequests(
                        authz -> authz
                                // Public endpoints - no authentication required
                                // Anyone can access "/" and "/login"
                                .requestMatchers("/", "/login").permitAll()
                                
                                // All other endpoints require authentication
                                // User must provide valid JWT token
                                .anyRequest().authenticated())
                
                // Enable JWT-based authentication for this resource server
                // When a request comes with "Authorization: Bearer <token>":
                // 1. Extract the token
                // 2. Validate using JwtDecoder bean
                // 3. If valid, set authentication in SecurityContext
                .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()))
                
                // Disable default Spring Security login form
                // We use custom REST endpoint /login instead
                .formLogin(f -> f.disable())
                
                // Session Management - STATELESS mode
                // No HttpSession created or used
                // Perfect for REST APIs - each request is independent
                // Client must send JWT token with every request
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

    /**
     * =========================================================================
     * JWT ENCODER BEAN
     * =========================================================================
     * Creates (signs) JWT tokens when user logs in successfully
     * 
     * WHAT IS JWT?
     * ------------
     * JWT = JSON Web Token
     * Format: header.payload.signature
     * Example: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyQGVtYWlsLmNvbSJ9.abc123
     * 
     * Parts:
     * 1. Header: Algorithm info (HS256, RS256, etc.)
     * 2. Payload: User data (claims) - subject, expiration, custom data
     * 3. Signature: Verification that token wasn't tampered
     * 
     * ENCODING PROCESS:
     * -----------------
     * Claims (user info) + Secret Key → JwtEncoder.encode() → JWT String
     * 
     * The signature ensures:
     * - Token was created by this server (has correct secret key)
     * - Token hasn't been modified since creation
     * 
     * USED IN: SecurityUtil.createToken() method
     */
    @Bean
    public JwtEncoder jwtEncoder() {
        // ImmutableSecret wraps our secret key for the encoder
        // NimbusJwtEncoder is the implementation from nimbus-jose-jwt library
        return new NimbusJwtEncoder(new ImmutableSecret<>(getSecretKey()));
    }

    /**
     * =========================================================================
     * JWT DECODER BEAN
     * =========================================================================
     * Validates JWT tokens on every protected request
     * 
     * WHAT IT VALIDATES:
     * ------------------
     * 1. Signature: Was this token signed with our secret key?
     * 2. Expiration: Is the token still valid (not expired)?
     * 3. Structure: Is the token properly formatted?
     * 
     * DECODING PROCESS:
     * -----------------
     * JWT String + Secret Key → JwtDecoder.decode() → Claims (user info)
     * 
     * IF VALIDATION FAILS:
     * --------------------
     * - Invalid signature → Token was tampered or wrong key
     * - Expired → User needs to login again
     * - Malformed → Not a valid JWT format
     * All result in 401 Unauthorized response
     * 
     * CALLED BY: Spring Security's OAuth2ResourceServer filter
     * (automatically on every request to protected endpoints)
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        // Build decoder with our secret key and algorithm
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder
                .withSecretKey(getSecretKey())
                .macAlgorithm(SecurityUtil.JWT_ALGORITHM)  // Must match encoder algorithm
                .build();
        
        // Return a lambda that decodes and logs any errors
        return token -> {
            try {
                return jwtDecoder.decode(token);
            } catch (Exception ex) {
                // Log decode errors for debugging
                // Common errors: expired token, invalid signature, malformed token
                System.out.println("JWT Decode error: " + ex.getMessage());
                throw ex;
            }
        };
    }

    /**
     * =========================================================================
     * GET SECRET KEY HELPER METHOD
     * =========================================================================
     * Converts the Base64-encoded secret key from properties into a SecretKey object
     * 
     * SECRET KEY REQUIREMENTS (by algorithm):
     * ---------------------------------------
     * - HS256: Minimum 32 bytes (256 bits)
     * - HS384: Minimum 48 bytes (384 bits)
     * - HS512: Minimum 64 bytes (512 bits)
     * 
     * WHY BASE64?
     * -----------
     * Binary data cannot be stored directly in .properties file
     * Base64 encoding converts binary → text (safe for config files)
     * 
     * SECURITY NOTE:
     * --------------
     * In production, store this key in:
     * - Environment variables
     * - Secret management service (AWS Secrets Manager, HashiCorp Vault)
     * - NOT in source code or git repository!
     */
    private SecretKey getSecretKey() {
        // Decode Base64 string to byte array
        byte[] keyBytes = Base64.from(jwtKey).decode();
        
        // Create SecretKeySpec with the algorithm name
        // SecretKeySpec implements SecretKey interface
        return new SecretKeySpec(keyBytes, 0, keyBytes.length, 
                SecurityUtil.JWT_ALGORITHM.getName());
    }

    /**
     * =========================================================================
     * MVC REQUEST MATCHER BUILDER BEAN
     * =========================================================================
     * Helper bean for matching request paths in Spring MVC
     * 
     * WHAT IT DOES:
     * -------------
     * Creates matchers that work correctly with Spring MVC's request mapping
     * Used internally by Spring Security to match URL patterns
     * 
     * WHY NEEDED:
     * -----------
     * - Ensures URL matching respects Spring MVC's path handling
     * - Handles servlet path, context path correctly
     * - Required for .requestMatchers() in SecurityFilterChain
     */
    @Bean
    public MvcRequestMatcher.Builder mvc(HandlerMappingIntrospector introspector) {
        return new MvcRequestMatcher.Builder(introspector);
    }
}
