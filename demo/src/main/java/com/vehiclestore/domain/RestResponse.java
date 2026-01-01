package com.vehiclestore.domain;

// Generic REST API response wrapper - All API responses use this format
// Provides consistent response structure for frontend:
// {
//   "statusCode": 200,
//   "error": null,
//   "message": "CALL API SUCCESS",
//   "data": { ... actual data ... }
// }
// <T> = Generic type, can hold any data type (User, List<User>, LoginDTO, etc.)
public class RestResponse<T> {
    private int statusCode; // HTTP status code (200, 400, 401, 403, 500...)
    private String error; // Error type (null if success)
    private Object message; // Success/error message
    private T data; // Actual response data (generic type)

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public Object getMessage() {
        return message;
    }

    public void setMessage(Object message) {
        this.message = message;
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }

}
