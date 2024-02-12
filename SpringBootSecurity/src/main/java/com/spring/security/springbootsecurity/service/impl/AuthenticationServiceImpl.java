package com.spring.security.springbootsecurity.service.impl;

import com.spring.security.springbootsecurity.model.JwtAuthenticationResponse;
import com.spring.security.springbootsecurity.model.SignInRequest;
import com.spring.security.springbootsecurity.model.SignUpRequest;
import com.spring.security.springbootsecurity.model.User;
import com.spring.security.springbootsecurity.model.enums.Role;
import com.spring.security.springbootsecurity.repository.UserRepository;
import com.spring.security.springbootsecurity.service.AuthenticationService;
import com.spring.security.springbootsecurity.service.JwtService;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Override
    public JwtAuthenticationResponse signUp(SignUpRequest signUpRequest) {
        User user = User.builder()
                .firstName(signUpRequest.getFirstName())
                .lastName(signUpRequest.getLastName())
                .email(signUpRequest.getEmail())
                .password(passwordEncoder.encode(signUpRequest.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);
        String token = jwtService.generateToken(user);
        return JwtAuthenticationResponse.builder().token(token).build();
    }

    @Override
    public JwtAuthenticationResponse signin(SignInRequest signInRequest) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                signInRequest.getEmail(), signInRequest.getPassword()
        ));
        User user = userRepository.findByEmail(signInRequest.getEmail()).orElseThrow(() -> new IllegalArgumentException("Invalid Username or password"));
        String token = jwtService.generateToken(user);
        return JwtAuthenticationResponse.builder().token(token).build();
    }
}
