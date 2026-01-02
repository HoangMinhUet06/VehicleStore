package com.vehiclestore.controller;

import com.vehiclestore.util.error.IdInvalidException;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;

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
