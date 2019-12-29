package com.ryulth.springsecurityrestjwt.service;

import com.ryulth.springsecurityrestjwt.model.LoginRequest;
import com.ryulth.springsecurityrestjwt.model.Token;
import com.ryulth.springsecurityrestjwt.model.User;
import com.ryulth.springsecurityrestjwt.model.UserDto;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class TokenAuthenticationService implements UserAuthenticationService {
    private final TokenService tokenService;
    private final UserService userService;

    public TokenAuthenticationService(TokenService tokenService, UserService userService) {
        this.tokenService = tokenService;
        this.userService = userService;
    }

    @Override
    public Optional<Token> login(LoginRequest loginRequest) throws IllegalAccessException {
        User user = userService.findByEmail(loginRequest.getEmail());
        if (userService.equalsPassword(loginRequest.getPassword(), user.getPassword())) {
            return Optional.ofNullable(tokenService.generatedToken(UserDto.builder()
                    .id(user.getId())
                    .email(user.getEmail())
                    .build()));
        }
        throw new IllegalAccessException("Login fail");
    }

    @Override
    public Optional<User> findByToken(String token) {
        UserDto userDto = tokenService.verifyToken(token, true);
        return Optional.ofNullable(userService.findById(userDto.getId()));
    }

    @Override
    public void logout(User user) {

    }
}
