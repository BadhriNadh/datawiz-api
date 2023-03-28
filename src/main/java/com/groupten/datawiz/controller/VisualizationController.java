package com.groupten.datawiz.controller;
import com.groupten.datawiz.model.Visualization;
import com.groupten.datawiz.protocol.Response;
import com.groupten.datawiz.service.VisualizationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/visualization")
public class VisualizationController extends Handler{

    @Autowired
    VisualizationService visualizationService;

    @PostMapping("/save")
    public ResponseEntity<Response> saveVisualization(@RequestBody Visualization visualization){

        Response response = new Response(visualizationService.saveVisualization(visualization), HttpStatus.CREATED.value(), HttpStatus.CREATED.name());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/edit")
    public ResponseEntity<Response> editVisualization(@RequestBody Visualization visualization){
        Response response = new Response(visualizationService.editVisualization(visualization), HttpStatus.ACCEPTED.value(), HttpStatus.ACCEPTED.name());
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }

    @GetMapping("/get/{id}/{page}")
    public ResponseEntity<Response> getVisualization(@PathVariable("id") int connectionID, @PathVariable("page") int page){
        Response response = new Response(
                visualizationService.getVisualizationsValuesByConnectionId(connectionID, page),
                HttpStatus.OK.value(),
                HttpStatus.OK.name(),
                visualizationService.getTotalPages(connectionID, page)
        );
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @GetMapping("/get/{id}")
    public ResponseEntity<Response> getVisualizations(@PathVariable("id") int visualId){
        Response response = new Response(visualizationService.getVisualizationById(visualId), HttpStatus.OK.value(), HttpStatus.OK.name());
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @DeleteMapping("/remove/{id}")
    public ResponseEntity<Response> deleteVisualizations(@PathVariable("id") int visualId){
        Response response = new Response(visualizationService.deleteVisualization(visualId), HttpStatus.OK.value(), HttpStatus.OK.name());
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }


    @GetMapping("/values/{id}")
    public ResponseEntity<Response> getValuesById(@PathVariable("id") int id) {
        Response response = new Response(visualizationService.getData(id), HttpStatus.OK.value(), HttpStatus.OK.name());
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }
}
