package com.ryulth.springsecurityrestjwt.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor
public class UserDto {
    protected UserDto(){}
    private Long id;
    private String email;
}
