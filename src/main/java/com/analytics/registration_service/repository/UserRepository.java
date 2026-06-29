package com.analytics.registration_service.repository;

import com.analytics.registration_service.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);
    boolean existsByEmail(String email);

    @Modifying
    @Query("Update User u set u.tokenVersion = u.tokenVersion+1 where u.id = : userId")
    void incrementTokenVersion(@Param("userId") Long userId);
}

