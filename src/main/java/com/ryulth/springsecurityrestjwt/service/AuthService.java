package com.ryulth.springsecurityrestjwt.service;

import com.ryulth.springsecurityrestjwt.model.LoginRequest;
import com.ryulth.springsecurityrestjwt.model.RegisterRequest;
import com.ryulth.springsecurityrestjwt.model.Token;
import com.ryulth.springsecurityrestjwt.model.User;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    private final PasswordEncoder passwordEncoder;
    private final UserAuthenticationService userAuthenticationService;
    private final UserService userService;

    public AuthService(UserAuthenticationService userAuthenticationService, UserService userService) {
        this.userAuthenticationService = userAuthenticationService;
        this.userService = userService;
        this.passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    public Token register(RegisterRequest registerRequest) throws IllegalAccessException {
        userService.save(User.builder()
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .username(registerRequest.getPassword())
                .build());
        return login(LoginRequest.builder()
                .email(registerRequest.getEmail())
                .password(registerRequest.getPassword())
                .build());
    }
    public Token login(LoginRequest loginRequest) throws IllegalAccessException {
        return userAuthenticationService.login(loginRequest)
                .orElseThrow(RuntimeException::new);
    }
}
