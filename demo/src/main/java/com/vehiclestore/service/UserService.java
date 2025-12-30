package com.vehiclestore.service;

import org.springframework.stereotype.Service;
import com.vehiclestore.repository.UserRepository;
import com.vehiclestore.domain.User;

@Service
public class UserService {
    private final UserRepository userRepository;

    // Dependency Injection to get UserRepository instance
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // Handle creating a new user and retrurn the created user
    public User handleCreateUser(User user) {
        return this.userRepository.save(user); // Save to MySQL
    }
}