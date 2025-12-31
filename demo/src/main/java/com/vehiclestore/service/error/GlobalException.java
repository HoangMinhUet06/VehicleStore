package com.vehiclestore.service.error;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.vehiclestore.domain.RestResponse;

//Catch exceptions from all controllers and format error responses consistently
//When an exception occurs, look in the class containing `@RestControllerAdvice` and call the correct handler(@ExceptionHandler)
//If you don't have @RestControllerAdvice, this only applies within that specific controller, not globally.
@RestControllerAdvice
public class GlobalException {

    @ExceptionHandler(value = IdInvalidException.class)
    public ResponseEntity<RestResponse<Object>> handleIdInvalidException(IdInvalidException idException) {

        RestResponse<Object> res = new RestResponse<Object>();

        res.setStatusCode(HttpStatus.BAD_REQUEST.value());
        res.setMessage(idException.getMessage());
        res.setMessage("ID is invalid");

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(res);
    }

    // Add more exception handlers as needed

}
