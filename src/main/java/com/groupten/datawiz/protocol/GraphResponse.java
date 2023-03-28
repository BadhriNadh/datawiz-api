package com.groupten.datawiz.protocol;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

public class GraphResponse {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Integer visualizationId;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String name;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String schema;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String tableOne;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String tableTwo;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String columnX;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String columnY;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String calculation;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String graphType;

    private List<Object> x;
    private List<Object> y;

    public GraphResponse(List<Object> x, List<Object> y) {
        this.x = x;
        this.y = y;
    }

    public GraphResponse(String name, String schema, String tableOne, String tableTwo, String columnX, String columnY, String calculation, String graphType, List<Object> x, List<Object> y) {
        this.name = name;
        this.schema = schema;
        this.tableOne = tableOne;
        this.tableTwo = tableTwo;
        this.columnX = columnX;
        this.columnY = columnY;
        this.calculation = calculation;
        this.graphType = graphType;
        this.x = x;
        this.y = y;
    }

    public GraphResponse(Integer visualizationId, String name, String tableOne, String tableTwo, String columnX, String columnY, String graphType, List<Object> x, List<Object> y) {
        this.visualizationId = visualizationId;
        this.name = name;
        this.tableOne = tableOne;
        this.tableTwo = tableTwo;
        this.columnX = columnX;
        this.columnY = columnY;
        this.graphType = graphType;
        this.x = x;
        this.y = y;
    }

    public Integer getVisualizationId() {
        return visualizationId;
    }

    public void setVisualizationId(Integer visualizationId) {
        this.visualizationId = visualizationId;
    }

    public String getGraphType() {
        return graphType;
    }

    public void setGraphType(String graphType) {
        this.graphType = graphType;
    }

    public List<Object> getX() {
        return x;
    }

    public void setX(List<Object> x) {
        this.x = x;
    }

    public List<Object> getY() {
        return y;
    }

    public void setY(List<Object> y) {
        this.y = y;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSchema() {
        return schema;
    }

    public void setSchema(String schema) {
        this.schema = schema;
    }

    public String getTableOne() {
        return tableOne;
    }

    public void setTableOne(String tableOne) {
        this.tableOne = tableOne;
    }

    public String getTableTwo() {
        return tableTwo;
    }

    public void setTableTwo(String tableTwo) {
        this.tableTwo = tableTwo;
    }

    public String getColumnX() {
        return columnX;
    }

    public void setColumnX(String columnX) {
        this.columnX = columnX;
    }

    public String getColumnY() {
        return columnY;
    }

    public void setColumnY(String columnY) {
        this.columnY = columnY;
    }

    public String getCalculation() {
        return calculation;
    }

    public void setCalculation(String calculation) {
        this.calculation = calculation;
    }
}
