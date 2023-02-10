package com.groupten.datawiz.controller;

import com.groupten.datawiz.model.User;
import com.groupten.datawiz.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    UserService userService;

    @GetMapping("/message")
    public String home() {
        return "Never give up!!";
    }

    @PostMapping("/save")
    public ResponseEntity<User> saveUser(@RequestBody User user) {
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.saveUser(user));
    }

    @PostMapping("/login")
    public ResponseEntity<String> token(Authentication authentication) {
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(userService.generateToken(authentication));
    }
}
