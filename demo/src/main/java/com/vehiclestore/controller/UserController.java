package com.vehiclestore.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import com.vehiclestore.service.UserService;
import com.vehiclestore.domain.User;

@RestController
public class UserController {

    private final UserService userService;

    // Constructor, Spring auto inject UserService
    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/user/create")
    public String createNewUser() {
        User user = new User();
        user.setName("Ryan Lee");
        user.setEmail("hoangminhaaz@gmail.com");
        user.setPassword("12345678");

        this.userService.handleCreateUser(user);
        return "Create new user successfully!";
    }
}