package com.groupten.datawiz.controller;
import com.groupten.datawiz.model.DbConn;
import com.groupten.datawiz.protocol.Response;
import com.groupten.datawiz.service.DbConnService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController
@RequestMapping("/connection")
public class ConnectionController extends Handler{

    @Autowired
    DbConnService dbConnService;

    @PostMapping("/save")
    public ResponseEntity<Response> saveConn(@RequestBody DbConn dbConn) {
        Response response = new Response(dbConnService.saveConn(dbConn).getId(),HttpStatus.CREATED.value(), HttpStatus.CREATED.name());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/edit")
    public ResponseEntity<Response> editConn(@RequestBody DbConn dbConn) {
        Response response = new Response(dbConnService.editConn(dbConn).getId(),HttpStatus.CREATED.value(), HttpStatus.CREATED.name());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/get/{id}")
    public ResponseEntity<Response> getConnById(@PathVariable("id") int id){
        Response response = new Response(dbConnService.findDbConnById(id),HttpStatus.OK.value(), HttpStatus.OK.name());
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @GetMapping("/getAll/{userid}")
    public ResponseEntity<Response> getAllConnByUserId(@PathVariable("userid") int user_id){
        Response response = new Response(dbConnService.getAllConnByUserId(user_id),HttpStatus.OK.value(), HttpStatus.OK.name());
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @DeleteMapping("/deleteById/{id}")
    public ResponseEntity<Response> deleteConnById(@PathVariable("id") int id){
        Response response = new Response(dbConnService.deleteConnById(id),HttpStatus.OK.value(), HttpStatus.OK.name());
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @PostMapping("/test")
    public ResponseEntity<Response> testConnection(@RequestBody DbConn dbConn){
        Response response = new Response(dbConnService.testConn(dbConn),HttpStatus.OK.value(), HttpStatus.OK.name());
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }
}
