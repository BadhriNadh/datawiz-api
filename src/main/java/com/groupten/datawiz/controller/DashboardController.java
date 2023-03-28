package com.groupten.datawiz.controller;

import com.groupten.datawiz.model.Dashboard;
import com.groupten.datawiz.protocol.Response;
import com.groupten.datawiz.service.DashboardService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/dashboard")
public class DashboardController extends Handler{

    @Autowired
    DashboardService dashboardService;

    @PostMapping("/save")
    public ResponseEntity<Response> saveDashboard(@RequestBody Dashboard dashboard){
        Response response = new Response(dashboardService.saveDashboard(dashboard).getDashboardId(), HttpStatus.ACCEPTED.value(), HttpStatus.ACCEPTED.name());
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }

    @GetMapping("/getSchemas/{userId}")
    public ResponseEntity<Response> getSchemas(@PathVariable("userId") int userId){
        Response response = new Response(dashboardService.getSchemas(userId), HttpStatus.CREATED.value(), HttpStatus.CREATED.name());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/getVisualisationIds/{userId}/{schema}")
    public ResponseEntity<Response> getVisualisationIds(@PathVariable("userId") int userId,@PathVariable("schema") String schema){
        Response response = new Response(dashboardService.getVisualisationIds(userId,schema), HttpStatus.CREATED.value(), HttpStatus.CREATED.name());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/graphs/values/{id}")
    public ResponseEntity<Response> getDashboardValues(@PathVariable("id") int id){
        Response response = new Response(dashboardService.getDashboardGraphs(id), HttpStatus.ACCEPTED.value(), HttpStatus.ACCEPTED.name());
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }

    @GetMapping("/get/{id}/{pageNumber}")
    public ResponseEntity<Response> getAllDashboards(@PathVariable("id") int id,@PathVariable("pageNumber") int pageNumber){

        var dashboards =dashboardService.getAllDashboards(id, pageNumber);
        Response response = new Response(
                dashboards.get().toList(),
                HttpStatus.ACCEPTED.value(),
                HttpStatus.ACCEPTED.name(),
                dashboards.getTotalPages()
        );
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }



    @DeleteMapping("/delete/{id}")
    public  ResponseEntity<Response> deleteDashboard(@PathVariable("id") int id){
        dashboardService.deleteDashboard(id);
        Response response = new Response(id, HttpStatus.OK.value(), HttpStatus.OK.name());
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

}
