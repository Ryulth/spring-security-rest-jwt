package com.ryulth.springsecurityrestjwt.service;

import com.ryulth.springsecurityrestjwt.model.LoginRequest;
import com.ryulth.springsecurityrestjwt.model.Token;
import com.ryulth.springsecurityrestjwt.model.User;

import java.util.Optional;

public interface UserAuthenticationService {
    Optional<Token> login(LoginRequest loginRequest) throws IllegalAccessException;
    Optional<User> findByToken(String token);
    void logout(User user);
}
