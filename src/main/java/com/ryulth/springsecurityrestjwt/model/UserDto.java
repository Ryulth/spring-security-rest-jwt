package com.ryulth.springsecurityrestjwt.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

@Getter
@Builder
@AllArgsConstructor
@ToString
public class UserDto {
    protected UserDto(){}
    private Long id;
    private String email;
}
