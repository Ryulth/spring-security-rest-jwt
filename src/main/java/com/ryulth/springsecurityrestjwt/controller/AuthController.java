package com.ryulth.springsecurityrestjwt.controller;

import com.ryulth.springsecurityrestjwt.model.LoginRequest;
import com.ryulth.springsecurityrestjwt.model.RegisterRequest;
import com.ryulth.springsecurityrestjwt.model.Token;
import com.ryulth.springsecurityrestjwt.service.AuthService;
import io.swagger.annotations.ApiOperation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @ApiOperation("register API")
    @Transactional
    @PostMapping("/register")
    public Token register(@RequestBody RegisterRequest registerRequest) throws IllegalAccessException {
        return authService.register(registerRequest);
    }

    @ApiOperation("login API")
    @PostMapping("/login")
    public Token register(@RequestBody LoginRequest loginRequest) throws IllegalAccessException {
        return authService.login(loginRequest);
    }
}
