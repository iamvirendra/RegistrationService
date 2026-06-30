package com.analytics.registration_service.service;

import com.analytics.registration_service.dto.request.LoginRequest;
import com.analytics.registration_service.dto.request.RegisterRequest;
import com.analytics.registration_service.dto.response.AuthResponse;
import com.analytics.registration_service.entity.RefreshToken;
import com.analytics.registration_service.entity.Role;
import com.analytics.registration_service.entity.User;
import com.analytics.registration_service.exception.EmailAlreadyExistsException;
import com.analytics.registration_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final AuthenticationManager authenticationManager;

    private AuthResponse buildAuthResponse(User user){
        String accessToken = jwtService.generateAccessToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        return AuthResponse.builder()
                .refreshToken(refreshToken.getToken())
                .accessToken(accessToken)
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .role(user.getRole().name())
                .build();
    }

    // Register
    @Transactional
    public AuthResponse register(RegisterRequest request){
        if(userRepository.existsByEmail(request.getEmail())){
            throw new EmailAlreadyExistsException("Email already registered: " + request.getEmail());
        }

        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .role(Role.USER)
                .tokenVersion(0)
                .build();

        userRepository.save(user);
        log.info("New User registered: {}", user.getEmail());
        return buildAuthResponse(user);
    }

    //Login
    @Transactional
    public AuthResponse login(LoginRequest request){
        //Spring Security
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException(("User not found")));

        log.info("User LoggedIn: {}", user.getEmail());
        return buildAuthResponse(user);
    }

    //logout
    @Transactional
    public void logout(User user){
        refreshTokenService.revokeAllUserToken(user);
        log.info("User logged out: {}",user.getEmail());
    }

    //Invalidate all token for a user
    public void invalidateAllToken(Long userId){
        userRepository.incrementTokenVersion(userId);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        refreshTokenService.revokeAllUserToken(user);
        log.info("All token invalidated for userId: {}", userId);
    }

    //refresh token
    public AuthResponse refreshToken(String refreshTokenValue){
        RefreshToken refreshToken = refreshTokenService.verifyRefreshToken(refreshTokenValue);
        User user = refreshToken.getUser();
        refreshToken.setRevoked(true);

        String newAccessToken = jwtService.generateAccessToken(user);
        RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user);

        log.info("Token refreshed for user: {}", user.getEmail());
        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken.getToken())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .role(user.getRole().name())
                .build();
    }

}
