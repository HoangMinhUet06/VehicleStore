package com.vehiclestore.controller;

import org.springframework.security.core.Authentication;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.vehiclestore.domain.dto.LoginDTO;
import com.vehiclestore.domain.dto.ResponseLoginDTO;
import com.vehiclestore.util.SecurityUtil;

import jakarta.validation.Valid;

// Controller handling authentication endpoints (login, logout, etc.)
@RestController
public class AuthController {

    // AuthenticationManagerBuilder - Spring's tool to build and access
    // AuthenticationManager
    // AuthenticationManager is responsible for authenticating users
    private final AuthenticationManagerBuilder authenticationMangerBuilder;

    private final SecurityUtil securityUtil;

    public AuthController(AuthenticationManagerBuilder authenticationMangerBuilder, SecurityUtil securityUtil) {
        this.authenticationMangerBuilder = authenticationMangerBuilder;
        this.securityUtil = securityUtil;
    }

    // Login endpoint - receives username (email) and password from client
    // Authentication flow:
    // 1. Client sends POST /login with {username, password}
    // 2. Create UsernamePasswordAuthenticationToken (unauthenticated)
    // 3. AuthenticationManager.authenticate() triggers the authentication process:
    // -> DaoAuthenticationProvider
    // -> UserDetailCustom.loadUserByUsername()
    // -> BCryptPasswordEncoder.matches(inputPassword, hashedPassword)
    // 4. If success: return authenticated Authentication object
    // If fail: throw BadCredentialsException (403 error)
    @PostMapping("/login")
    public ResponseEntity<ResponseLoginDTO> login(@Valid @RequestBody LoginDTO loginDTO) {

        // Step 1: Wrap username and password into an authentication token
        // This token is NOT authenticated yet - just holds the credentials
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                loginDTO.getUsername(), // In our app, username = email
                loginDTO.getPassword()); // Plain text password from user input

        // Step 2: Authenticate the token
        // This calls: DaoAuthenticationProvider ->
        // UserDetailCustom.loadUserByUsername()
        // If password matches: returns authenticated Authentication object
        // If password wrong: throws BadCredentialsException
        Authentication authentication = authenticationMangerBuilder.getObject().authenticate(authenticationToken);

        // Step 3: If we reach here, authentication was successful
        // Create a token
        String accessToken = this.securityUtil.createToken(authentication);
        ResponseLoginDTO response = new ResponseLoginDTO();
        response.setAccessToken(accessToken);
        return ResponseEntity.ok().body(response);
    }
}
