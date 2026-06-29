package com.analytics.registration_service.dto.request;

import jakarta.validation.constraints.NotBlank;

public class RefreshTokenRequest {

    @NotBlank(message = "token can't be empty")
    private String refreshToken;
}
