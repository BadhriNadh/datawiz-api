package com.groupten.datawiz.service;
import com.groupten.datawiz.model.Visualization;
import com.groupten.datawiz.protocol.GraphRequest;
import com.groupten.datawiz.protocol.GraphResponse;
import com.groupten.datawiz.repository.VisualizationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

@Service
@Transactional
public class VisualizationServiceImpl implements VisualizationService{

    @Autowired
    GraphService graphService;
    @Autowired
    VisualizationRepository visualizationRepository;

    @Override
    public int saveVisualization(Visualization visualization){
        Visualization visualizationSave = new Visualization(
                visualization.getConnectionId(),
                visualization.getSchemaName(),
                visualization.getUserId(),
                visualization.getName(),
                visualization.getChartType(),
                visualization.getxTable(),
                visualization.getxAttribute(),
                visualization.getyTable(),
                visualization.getyAttribute(),
                visualization.getCalculation(),
                Timestamp.from(Instant.now())
        );
        return visualizationRepository.save(visualizationSave).getVisualizationId();
    }

    @Override
    public int editVisualization(Visualization visualization){
        Visualization visualizationUpdate = new Visualization(
                visualization.getVisualizationId(),
                visualization.getConnectionId(),
                visualization.getSchemaName(),
                visualization.getUserId(),
                visualization.getName(),
                visualization.getChartType(),
                visualization.getxTable(),
                visualization.getxAttribute(),
                visualization.getyTable(),
                visualization.getyAttribute(),
                visualization.getCalculation(),
                Timestamp.from(Instant.now())
        );
        return visualizationRepository.save(visualizationUpdate).getVisualizationId();
    }

    @Override
    public Visualization getVisualizationById(int id){
        return visualizationRepository.findById(id).orElse(null);
    }

    @Override
    public List<GraphResponse> getVisualizationsValuesByConnectionId(int connectionId, int page) {
        Pageable pageable =  PageRequest.of(page, 6, Sort.by("updatedAt"));
        var visuals = visualizationRepository.findByConnectionIdAndDeletedAt(connectionId,null,pageable);

        List<GraphResponse> responses = new LinkedList<>();

        visuals.get().toList().forEach(visualization -> {
            var graphServiceResponse =graphService.getGraphValues(
                 new GraphRequest(
                        visualization.getSchemaName(),
                        visualization.getxTable(),
                        visualization.getyTable(),
                        visualization.getxAttribute(),
                        visualization.getyAttribute(),
                        visualization.getCalculation(),
                        visualization.getConnectionId()
                ));

            var graphResponse = new GraphResponse(
                    visualization.getVisualizationId(),
                    visualization.getName(),
                    visualization.getxTable(),
                    visualization.getyTable(),
                    visualization.getxAttribute(),
                    visualization.getyAttribute(),
                    visualization.getChartType(),
                    graphServiceResponse.getX(),
                    graphServiceResponse.getY()
            );

            responses.add(graphResponse);
        });
        return responses;
    }

    @Override
    public int getTotalPages(int connectionId, int page) {
        Pageable pageable =  PageRequest.of(page, 6, Sort.by("updatedAt"));
        var visuals = visualizationRepository.findByConnectionIdAndDeletedAt(connectionId,null,pageable);

        return visuals.getTotalPages();
    }

    @Override
    public String deleteVisualization(int visualId) {
        visualizationRepository.updateDeletedAtTime(visualId, Timestamp.from(Instant.now()));
        return "Deleted";
    }

    @Override
    public GraphResponse getData(int id){

        Visualization visualization=getVisualizationById(id);

        GraphResponse graphServiceResponse = graphService.getGraphValues(
                new GraphRequest(
                        visualization.getSchemaName(),
                        visualization.getxTable(),
                        visualization.getyTable(),
                        visualization.getxAttribute(),
                        visualization.getyAttribute(),
                        visualization.getCalculation(),
                        visualization.getConnectionId()
                )
        );

        return new GraphResponse(
                visualization.getName(),
                visualization.getSchemaName(),
                visualization.getxTable(),
                visualization.getyTable(),
                visualization.getxAttribute(),
                visualization.getyAttribute(),
                visualization.getCalculation(),
                visualization.getChartType(),
                graphServiceResponse.getX(),
                graphServiceResponse.getY());
    }
}
