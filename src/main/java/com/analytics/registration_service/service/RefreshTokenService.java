package com.analytics.registration_service.service;

import com.analytics.registration_service.entity.RefreshToken;
import com.analytics.registration_service.entity.User;
import com.analytics.registration_service.exception.TokenException;
import com.analytics.registration_service.repository.RefreshTokenRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    @Transactional
    public RefreshToken createRefreshToken(User user){
        long activeSessions = refreshTokenRepository.countActiveTokensByUser(LocalDateTime.now(), user);

        if(activeSessions >= 5){
            refreshTokenRepository.revokeAllUserTokens(user);
            log.warn("Max session reached for user: {}. All tokens revoked.", user.getEmail());
        }

        RefreshToken refreshToken = RefreshToken.builder()
                .token(UUID.randomUUID().toString())
                .user(user)
                .expiresAt(LocalDateTime.now().plusSeconds(refreshTokenExpiration/1000))
                .revoked(false)
                .build();
        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional
    public RefreshToken verifyRefreshToken(String token){
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                                        .orElseThrow(() -> new TokenException(
                                                "RefreshToken not found."
                                        ));
        if(refreshToken.isRevoked()){
            refreshTokenRepository.revokeAllUserTokens(refreshToken.getUser());
            log.warn("Revoked token reuse detected for user: {}. " + "All tokens revoked.",
                    refreshToken.getUser().getEmail());
            throw new TokenException("Refresh token has been revoked.Please login again.");
        }

        if(refreshToken.isExpired()){
            refreshTokenRepository.delete(refreshToken);
            log.info("Expired refresh token deleted for user: {}", refreshToken.getUser().getEmail());
            throw new TokenException("Refresh token has expired. Please login again.");
        }
        return refreshToken;
    }

    @Scheduled(cron = "0 0 2 * * ?")
    @Transactional
    public void cleanUpExpiredToken(){
        log.info("Starting expired token cleanup job ....");
        refreshTokenRepository.deleteExpiredTokens(LocalDateTime.now());
        log.info("Expired token Cleanup Job completed.");
    }

    @Transactional
    public void revokeAllUserToken(User user) {
        refreshTokenRepository.revokeAllUserTokens(user);
        log.info("All refresh token revoked for user: {}", user.getEmail());
    }
}
