package com.spring.security.springbootsecurity.service;

import com.spring.security.springbootsecurity.model.JwtAuthenticationResponse;
import com.spring.security.springbootsecurity.model.SignInRequest;
import com.spring.security.springbootsecurity.model.SignUpRequest;

public interface AuthenticationService {
    JwtAuthenticationResponse signUp(SignUpRequest signUpRequest);

    JwtAuthenticationResponse signin(SignInRequest signInRequest);
}
