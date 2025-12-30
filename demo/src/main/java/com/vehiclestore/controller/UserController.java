package com.vehiclestore.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
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

    @PostMapping("/user/create")

    public User createNewUser(
            @RequestBody User postManUser) {

        User newUser = this.userService.handleCreateUser(postManUser);
        return newUser;
    }
}