package com.ryulth.springsecurityrestjwt.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor
public class RegisterRequest {
    protected RegisterRequest(){}
    private String email;
    private String password;
    private String username;
}
