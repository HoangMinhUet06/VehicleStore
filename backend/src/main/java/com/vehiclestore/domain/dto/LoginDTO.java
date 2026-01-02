package com.vehiclestore.domain.dto;

import jakarta.validation.constraints.NotBlank;

// DTO (Data Transfer Object) for login request
// This class receives data from POST /login request body
// Used to transfer login credentials from client to server
// Note: 'username' in this app is actually the user's email
public class LoginDTO {
    @NotBlank(message = "Username is required")
    private String username; // User's email address (used for authentication)

    @NotBlank(message = "Password is required")
    private String password; // Plain text password (will be compared with hashed password in DB)

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

}
