package com.groupten.datawiz.service;

import com.groupten.datawiz.model.Dashboard;
import com.groupten.datawiz.model.Visualization;
import com.groupten.datawiz.protocol.DashboardResponse;
import com.groupten.datawiz.protocol.GraphRequest;
import com.groupten.datawiz.protocol.GraphResponse;
import com.groupten.datawiz.repository.DashboardRepository;
import com.groupten.datawiz.repository.VisualizationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

@Service
@Transactional
public class DashboardServiceImpl implements DashboardService{

    @Autowired
    DashboardRepository dashboardRepository;

    @Autowired
    VisualizationRepository visualizationRepository;

    @Autowired
    GraphService graphService;

    @Override
    public Dashboard saveDashboard(Dashboard dashboard) {
        return dashboardRepository.save(dashboard);
    }

    @Override
    public DashboardResponse getDashboardGraphs(int id) {
        Dashboard dashboard = dashboardRepository.findById(id).get();

        List<Integer> visuals = new ArrayList<>();
        if(dashboard.getVisualOneId()!=null){ visuals.add(dashboard.getVisualOneId()); }
        if(dashboard.getVisualTwoId()!=null){ visuals.add(dashboard.getVisualTwoId()); }
        if(dashboard.getVisualThreeId()!=null){ visuals.add(dashboard.getVisualThreeId()); }
        if(dashboard.getVisualFourId()!=null){ visuals.add(dashboard.getVisualFourId()); }

        List<GraphResponse> responses = new LinkedList<>();
        if(!visuals.isEmpty()){
            List<Visualization> visualizations = new ArrayList<>();
            visuals.forEach(v -> visualizations.add(visualizationRepository.findById(v).get()));

            visualizations.forEach(visualization -> {
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
        }

        return new DashboardResponse(dashboard.getDashboardId(),dashboard.getName(), responses);
    }

    @Autowired
    VisualizationRepository VR;

    @Override
    public void deleteDashboard(int id) {
        dashboardRepository.deleteById(id);
    }
    public List<String> getSchemas(int userId){
        List<Visualization> visualizations=VR.findByUserId(userId);
        List<String> schemas=new ArrayList<String>();
        for(Visualization x:visualizations){
            if(!schemas.contains(x.getSchemaName())){
                schemas.add(x.getSchemaName());
            }
        }
        return schemas;
    }

    public List<Integer> getVisualisationIds(int userId,String schemaName){
        List<Visualization> visualizations=VR.findByUserIdAndSchemaName(userId,schemaName);
        List<Integer> visualisationIds=new ArrayList<Integer>();
        for(Visualization x:visualizations){
            if(!visualisationIds.contains(x.getVisualizationId())){
                visualisationIds.add(x.getVisualizationId());
            }
        }
        return visualisationIds;
    }
    @Override
    public Page<Dashboard> getAllDashboards(int id, int pageNumber) {
        Pageable pageable =  PageRequest.of(pageNumber, 4/*, Sort.by("updatedAt")*/);
        return dashboardRepository.findByUserId(id, pageable).get();
    }


}
