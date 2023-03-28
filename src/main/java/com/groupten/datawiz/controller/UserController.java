package com.groupten.datawiz.controller;

import com.groupten.datawiz.model.User;
import com.groupten.datawiz.protocol.Response;
import com.groupten.datawiz.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/user")
public class UserController extends Handler{

    @Autowired
    UserService userService;

    //For Testing only
    @GetMapping("/message")
    public String home() {
        return "Never give up!!";
    }

    @PostMapping("/save")
    public ResponseEntity<Response> saveUser(@RequestBody User user) {
        Response response = new Response(userService.saveUser(user).getUserId(),HttpStatus.ACCEPTED.value(), HttpStatus.ACCEPTED.name());
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }

    @GetMapping("/login")
    public ResponseEntity<Response> token(Authentication authentication) {
        Response response = new Response(userService.generateToken(authentication),HttpStatus.ACCEPTED.value(), HttpStatus.ACCEPTED.name());
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }

    @GetMapping("/me/{userName}")
    public ResponseEntity<Response> me(@PathVariable("userName") String userName) {
        Response response = new Response(userService.getUserId(userName),HttpStatus.OK.value(), HttpStatus.OK.name());
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }
}
