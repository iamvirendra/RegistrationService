package com.analytics.registration_service.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterRequest {
    @NotBlank(message = "First Name is Required")
    @Size(min = 2, max = 50, message = "First Name must be between 2 to 50 characters")
    private String firstName;

    @NotBlank(message = "Last Name is Required")
    @Size(min = 2, max = 2, message = "Last Name is between 2 to 50 characters")
    private String lastName;

    @NotBlank(message = "Password is mandatory")
    @Size(min = 8, message = "Password must be of at least 8 characters")
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
            message = "Password must contain at least one uppercase, one lowercase, one number and one special character"
    )
    private String password;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

}
