package com.ryulth.springsecurityrestjwt.service;

import com.ryulth.springsecurityrestjwt.model.User;
import com.ryulth.springsecurityrestjwt.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    public void save(User user) {
        userRepository.save(user);
    }

    public boolean equalsPassword(String requestPassword, String originPassword) {
        return passwordEncoder.matches(requestPassword, originPassword);
    }

    public User findById(Long id) {
        log.info("find by id :{}",id);
        return userRepository.findById(id)
                .orElseThrow(IllegalAccessError::new);
    }

    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(IllegalAccessError::new);
    }
}
