package com.vehiclestore.service;

import com.vehiclestore.domain.User;

import java.util.Collections;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

// Custom implementation of UserDetailsService - Spring Security's interface for loading user data
// This class is called automatically by DaoAuthenticationProvider during authentication
// Flow: Login request -> DaoAuthenticationProvider -> loadUserByUsername() -> return UserDetails
@Component("userDetailService")
public class UserDetailCustom implements UserDetailsService {

    private final UserService userService;

    public UserDetailCustom(UserService userService) {
        this.userService = userService;
    }

    // This method is called by Spring Security when user tries to login
    // Parameter 'username' comes from login request (in our case, it's email)
    // Must return UserDetails object containing: username, password (hashed), and
    // authorities (roles)
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // 1. Find user in database by email
        User user = this.userService.handleGetUserByUsername(username);

        // 2. Convert our User entity to Spring Security's User object
        // IMPORTANT: There are 2 different User classes!
        // - com.vehiclestore.domain.User = Our entity (database)
        // - org.springframework.security.core.userdetails.User = Spring Security's User
        // We use full package name to avoid confusion
        return new org.springframework.security.core.userdetails.User(
                user.getEmail(), // Username for authentication
                user.getPassword(), // Hashed password from DB (Spring will compare with input)
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))); // User's role/authority
    }
}
