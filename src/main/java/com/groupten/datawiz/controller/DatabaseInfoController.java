package com.groupten.datawiz.controller;
import com.groupten.datawiz.protocol.DbInfoRequest;
import com.groupten.datawiz.protocol.Response;
import com.groupten.datawiz.service.DbInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin
@RestController
@RequestMapping("/database")
public class DatabaseInfoController extends Handler{

    @Autowired
    DbInfoService dbInfoService;

    @PostMapping("/schemas")
    public ResponseEntity<Response> getDatabases(@RequestBody DbInfoRequest dbInfo) {
        Response response=new Response(dbInfoService.getDatabases(dbInfo),HttpStatus.OK.value(), HttpStatus.OK.name());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/schema/tables")
    public ResponseEntity<Response> getTables(@RequestBody DbInfoRequest dbInfo) {
        Response response=new Response(dbInfoService.getTables(dbInfo),HttpStatus.OK.value(), HttpStatus.OK.name());
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @PostMapping("/schema/table/columns")
    public ResponseEntity<Response> getColumns (@RequestBody DbInfoRequest dbInfo){
        Response response=new Response(dbInfoService.getColumns(dbInfo),HttpStatus.OK.value(), HttpStatus.OK.name());
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @PostMapping("/schema/table/integerColumns")
    public ResponseEntity<Response> getIntegerColumns (@RequestBody DbInfoRequest dbInfo){
        Response response=new Response(dbInfoService.getIntegerColumns(dbInfo),HttpStatus.OK.value(), HttpStatus.OK.name());
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }
}