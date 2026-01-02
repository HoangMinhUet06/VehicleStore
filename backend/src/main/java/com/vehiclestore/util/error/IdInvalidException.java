package com.vehiclestore.util.error;

// Custom Exception for invalid ID errors
// Thrown when user provides invalid ID (negative, zero, non-existent)
// Caught by GlobalException handler and returns proper error response
public class IdInvalidException extends Exception {

    public IdInvalidException(String message) {
        super(message);
    }
}
