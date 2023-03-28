package com.groupten.datawiz.protocol;

import com.groupten.datawiz.model.Dashboard;

import java.util.List;

public class DashboardResponse {

    private int id;
    private String name;
    private List<GraphResponse> values;

    public DashboardResponse(int id, String name, List<GraphResponse> values) {
        this.id = id;
        this.name = name;
        this.values = values;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<GraphResponse> getValues() {
        return values;
    }

    public void setValues(List<GraphResponse> values) {
        this.values = values;
    }
}
