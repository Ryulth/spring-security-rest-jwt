package com.ryulth.springsecurityrestjwt.service;

import com.ryulth.springsecurityrestjwt.model.Token;
import com.ryulth.springsecurityrestjwt.model.UserDto;

public interface TokenService {
    Token generatedToken(UserDto userDto);
    UserDto verifyToken(String token, boolean isAccess);
}
