package com.spring.security.springbootsecurity.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class SignInRequest {
    private String email;
    private String password;
}