package com.groupten.datawiz.controller;

import com.groupten.datawiz.protocol.GraphRequest;
import com.groupten.datawiz.protocol.Response;
import com.groupten.datawiz.service.GraphService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/graph/bar")
public class GraphController extends Handler {

    @Autowired
    GraphService graphService;

    @PostMapping("/value")
    public ResponseEntity<Response> gatValues(@RequestBody GraphRequest graphRequest) {
        Response response = new Response(graphService.getValues(graphRequest),HttpStatus.OK.value(), HttpStatus.OK.name());
        return ResponseEntity.ok(response);
    }
}
