package com.vehiclestore.controller;

import org.springframework.web.bind.annotation.RestController;

import com.vehiclestore.util.error.IdInvalidException;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@RestController
public class HelloController {

    @GetMapping("/")
    public String getHelloWorld() throws IdInvalidException {
        if (true) {
            throw new IdInvalidException("Demo Exception from HelloController");
        }
        return "Spring By Ryan Lee";
    }

}
