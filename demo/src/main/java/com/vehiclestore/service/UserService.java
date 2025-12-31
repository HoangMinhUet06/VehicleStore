package com.vehiclestore.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.vehiclestore.repository.UserRepository;
import com.vehiclestore.domain.User;

import java.util.List;

@Service
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    // Dependency Injection to get UserRepository instance
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // Handle creating a new user and retrurn the created user
    public User handleCreateUser(User user) {
        // Encrypt the password before saving
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return this.userRepository.save(user); // Save to MySQL
    }

    // Handle deleting a user by ID
    public void handleDeleteUser(long id) {
        this.userRepository.deleteById(id);
    }

    // Handle fetching a user by ID
    public User handleGetUserById(long id) {
        return this.userRepository.findById(id).orElse(null);
    }

    // Handle get all users
    public List<User> handleGetAllUsers() {
        return this.userRepository.findAll();
    }

    // Handle update user details
    public User handleUpdateUser(User updatedUser) {
        // Find user by id in database transmitted via json
        User currentUser = this.userRepository.findById(updatedUser.getId()).orElse(null);
        if (currentUser == null) {
            return null; // User not found
        }

        // Set new details after find by id
        currentUser.setName(updatedUser.getName());
        currentUser.setEmail(updatedUser.getEmail());
        currentUser.setPassword(updatedUser.getPassword());

        return this.userRepository.save(currentUser);
    }
}