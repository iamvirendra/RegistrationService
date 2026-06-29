package com.analytics.registration_service.repository;

import com.analytics.registration_service.entity.RefreshToken;
import com.analytics.registration_service.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    @Modifying
    @Query("Update RefreshToken rt set rt.revoked = true where rt.user = :user")
    void revokeAllUserTokens(@Param("user") User user);

    @Modifying
    @Query("Delete from RefreshToken rt where rt.expiresAt < :now and rt.revoked = true")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);

    @Query("Select count(rt) from RefreshToken rt where rt.revoked = false and rt.expiresAt > :now and rt.user = :user")
    long countActiveTokensByUser(@Param("now") LocalDateTime now, @Param("user") User user);
}
