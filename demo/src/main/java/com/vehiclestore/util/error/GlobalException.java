package com.vehiclestore.util.error;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.vehiclestore.domain.RestResponse;

//Catch exceptions from all controllers and format error responses consistently
//When an exception occurs, look in the class containing `@RestControllerAdvice` and call the correct handler(@ExceptionHandler)
//If you don't have @RestControllerAdvice, this only applies within that specific controller, not globally.
@RestControllerAdvice
public class GlobalException {

    // Handle multiple authentication/authorization exceptions
    @ExceptionHandler(value = {
            UsernameNotFoundException.class,
            BadCredentialsException.class
    })
    public ResponseEntity<RestResponse<Object>> handleIdInvalidException(Exception ex) {

        RestResponse<Object> res = new RestResponse<Object>();

        res.setStatusCode(HttpStatus.BAD_REQUEST.value());
        res.setError(ex.getMessage());
        res.setMessage("Exception occurred");

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(res);
    }

    // Handle validation errors from @Valid annotation (e.g., @NotBlank, @Email,
    // @Size...)
    // When validation fails, Spring throws MethodArgumentNotValidException
    // This handler catches it and returns a formatted error response with all
    // validation messages
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<RestResponse<Object>> validationError(MethodArgumentNotValidException ex) {
        BindingResult result = ex.getBindingResult();
        final List<FieldError> fieldErrors = result.getFieldErrors();

        RestResponse<Object> res = new RestResponse<Object>();
        res.setStatusCode(HttpStatus.BAD_REQUEST.value());
        res.setError(ex.getBody().getDetail());

        List<String> errors = fieldErrors.stream().map(f -> f.getDefaultMessage()).collect(Collectors.toList());
        res.setMessage(errors.size() > 1 ? errors : errors.get(0));

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(res);
    }

}
