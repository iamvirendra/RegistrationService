package com.analytics.registration_service.controller;

import com.analytics.registration_service.dto.request.LoginRequest;
import com.analytics.registration_service.dto.request.RefreshTokenRequest;
import com.analytics.registration_service.dto.request.RegisterRequest;
import com.analytics.registration_service.dto.response.AuthResponse;
import com.analytics.registration_service.entity.User;
import com.analytics.registration_service.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    //register
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request){
        AuthResponse response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    //login
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request){
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    //refresh
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request){
        AuthResponse response = authService.refreshToken(request.getRefreshToken());
        return ResponseEntity.ok(response);
    }

    //logout
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(Authentication authentication){
        User user  = (User) authentication.getPrincipal();
        authService.logout(user);
        return ResponseEntity.ok(Map.of("message", "Logged out Successfully"));
    }

    //Invalidate all tokens (Admin Only)
    @PostMapping("/invalidate/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> invalidateAllTokens(@PathVariable Long userId){
        authService.invalidateAllToken(userId);
        return ResponseEntity.ok(Map.of("message", "All tokens invalidated for userId: " + userId));
    }

    //get current user
    @GetMapping("/me")
    public ResponseEntity<Map<String, String>> getCurrentUser(Authentication authentication){
        User user = (User) authentication.getPrincipal();

        return ResponseEntity.ok(Map.of(
                "email", user.getEmail(),
                "firstName", user.getFirstName(),
                "lastName", user.getLastName(),
                "role", user.getRole().name()
        ));
    }
}
