package com.groupten.datawiz.service;

import com.groupten.datawiz.model.Dashboard;
import com.groupten.datawiz.protocol.DashboardResponse;
import org.springframework.data.domain.Page;

import java.util.List;

import java.util.List;

public interface DashboardService {

    Dashboard saveDashboard(Dashboard dashboard);

    List<String> getSchemas(int userId);
    List<Integer> getVisualisationIds(int userid, String schema);
    DashboardResponse getDashboardGraphs(int id);

    void deleteDashboard(int id);

    Page<Dashboard> getAllDashboards(int id, int pageNumber);

}
