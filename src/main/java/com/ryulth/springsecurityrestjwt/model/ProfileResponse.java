package com.ryulth.springsecurityrestjwt.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor
public class ProfileResponse {
    protected ProfileResponse(){}

    private String email;
    private String username;
}
