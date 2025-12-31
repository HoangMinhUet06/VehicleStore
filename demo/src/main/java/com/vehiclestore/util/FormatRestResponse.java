package com.vehiclestore.util;

import org.springframework.http.MediaType;
import org.springframework.core.MethodParameter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import com.vehiclestore.domain.RestResponse;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletResponse;

//Spring component to format all REST API responses in a consistent structure, for all controllers
//After controller methods return, this class intercepts the response and wraps it in RestResponse
//First, call supports() to check if formatting is needed
//Then, call beforeBodyWrite() to modify the response body before sending to client
@ControllerAdvice
public class FormatRestResponse implements ResponseBodyAdvice<Object> {

    @Override
    public boolean supports(MethodParameter returnType, Class converterType) {
        return true; // Apply to all responses
    }

    // Method to format the response body before sending it to the client
    @Override
    public Object beforeBodyWrite(Object body, MethodParameter returnType, MediaType selectedContentType,
            Class selectedConverterType, ServerHttpRequest request, ServerHttpResponse response) {

        HttpServletResponse servletResponse = ((ServletServerHttpResponse) response)
                .getServletResponse();

        int status = servletResponse.getStatus();

        RestResponse<Object> res = new RestResponse<Object>();
        res.setStatusCode(status);
        if (status >= 400) {
            // Case error
            return body; // Keep it, let GlobalException handle error responses
        } else {
            // Case success, wrap the body in RestResponse
            res.setData(body); // Original data from controller
            res.setMessage("CALL API SUCCESS");
        }
        return res;
    }
}