package com.analytics.registration_service.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class RefreshTokenRequest {

    @NotBlank(message = "token can't be empty")
    private String refreshToken;
}
