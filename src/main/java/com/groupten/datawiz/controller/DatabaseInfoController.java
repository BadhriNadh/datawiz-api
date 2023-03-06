package com.groupten.datawiz.controller;
import com.groupten.datawiz.model.DbConn;
import com.groupten.datawiz.model.UserDbInfo;
import com.groupten.datawiz.protocol.Response;
import com.groupten.datawiz.service.DbInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/DbInfo")
public class DatabaseInfoController extends Handler{

    @Autowired
    DbInfoService dbInfoService;

    @PostMapping("/getDatabases")
    public ResponseEntity<Response> getDatabases(@RequestBody UserDbInfo dbinfo) {
        Response response=new Response(dbInfoService.getDatabases(dbinfo),HttpStatus.OK.value(), HttpStatus.OK.name());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/getTables")
    public ResponseEntity<Response> getTables(@RequestBody UserDbInfo dbinfo) {
        Response response=new Response(dbInfoService.getTables(dbinfo),HttpStatus.OK.value(), HttpStatus.OK.name());
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @PostMapping("/getColumns")
    public ResponseEntity<Response> getColumns (@RequestBody UserDbInfo dbinfo){
        Response response=new Response(dbInfoService.getColumns(dbinfo),HttpStatus.OK.value(), HttpStatus.OK.name());
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }
}