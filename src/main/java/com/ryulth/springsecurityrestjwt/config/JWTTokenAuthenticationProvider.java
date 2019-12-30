package com.ryulth.springsecurityrestjwt.config;

import com.ryulth.springsecurityrestjwt.model.UserDto;
import com.ryulth.springsecurityrestjwt.service.UserAuthenticationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class JWTTokenAuthenticationProvider implements AuthenticationProvider {
    private final UserAuthenticationService userAuthenticationService;

    public JWTTokenAuthenticationProvider(UserAuthenticationService userAuthenticationService) {
        this.userAuthenticationService = userAuthenticationService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.info("authenticate : {}", authentication);
        Object token = authentication.getPrincipal();
        UserDto userDto = userAuthenticationService.verifyToken((String) token)
                .orElseThrow(() -> new IllegalArgumentException("Cannot find user with authentication token=" + token));
        log.info("verify user : {}",userDto);
        return authentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }
}
