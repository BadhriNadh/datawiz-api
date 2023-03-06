package com.groupten.datawiz.service;

import com.groupten.datawiz.model.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService {
    User saveUser(User user);

    String generateToken(Authentication authentication);

    int getUserId(String userName);
}
