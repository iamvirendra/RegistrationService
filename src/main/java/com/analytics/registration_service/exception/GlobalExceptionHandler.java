package com.analytics.registration_service.exception;

import com.analytics.registration_service.dto.response.ApiErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<ApiErrorResponse> handleEmailAlreadyExists(EmailAlreadyExistsException ex, HttpServletRequest request){
        log.warn("Email already exists: {}", ex.getMessage());
        return buildError(HttpStatus.CONFLICT, "Conflict", ex.getMessage(), request.getRequestURI());
    }

    @ExceptionHandler(TokenException.class)
    public ResponseEntity<ApiErrorResponse> handleTokenException(TokenException ex, HttpServletRequest request) {
        log.warn("Token error: {}", ex.getMessage());
        return buildError(HttpStatus.UNAUTHORIZED, "Unauthorised", ex.getMessage(), request.getRequestURI());
    }

    private ResponseEntity<ApiErrorResponse> buildError(HttpStatus status, String error, String message, String path){
        ApiErrorResponse response = ApiErrorResponse.builder()
                                    .status(status.value())
                                    .error(error)
                                    .message(message)
                                    .path(path)
                                    .timestamp(LocalDateTime.now())
                                    .build();

        return new ResponseEntity<>(response, status);
    }

}
