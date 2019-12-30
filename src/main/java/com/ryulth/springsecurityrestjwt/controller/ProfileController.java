package com.ryulth.springsecurityrestjwt.controller;

import com.ryulth.springsecurityrestjwt.model.ProfileResponse;
import com.ryulth.springsecurityrestjwt.model.User;
import io.swagger.annotations.ApiOperation;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ProfileController {

    @Deprecated
    @ApiOperation("profile API")
    @GetMapping("/profile")
    public ProfileResponse profileResponse(@AuthenticationPrincipal final User user){
        return ProfileResponse.builder()
                .email(user.getEmail())
                .username(user.getUsername())
                .build();
    }

    @ApiOperation("health API")
    @GetMapping("/tokencheck")
    public String  profileResponse(){
        return "Token Check";
    }
}
