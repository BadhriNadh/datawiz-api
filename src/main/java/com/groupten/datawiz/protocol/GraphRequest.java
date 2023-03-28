package com.groupten.datawiz.protocol;

public class GraphRequest {

    private String schemaName;
    private String tableNameOne;
    private String tableNameTwo;
    private String xColumn;
    private String yColumn;
    private String calculation;
    private int connectionId;

    public GraphRequest(String schemaName, String tableNameOne, String tableNameTwo, String xColumn, String yColumn, String calculation, int connectionId) {
        this.schemaName = schemaName;
        this.tableNameOne = tableNameOne;
        this.tableNameTwo = tableNameTwo;
        this.xColumn = xColumn;
        this.yColumn = yColumn;
        this.calculation = calculation;
        this.connectionId = connectionId;
    }

    public String getSchemaName() {
        return schemaName;
    }

    public void setSchemaName(String schemaName) {
        this.schemaName = schemaName;
    }

    public int getConnectionId() {
        return connectionId;
    }

    public void setConnectionId(int connectionId) {
        this.connectionId = connectionId;
    }

    public String getTableNameOne() {
        return tableNameOne;
    }

    public void setTableNameOne(String tableNameOne) {
        this.tableNameOne = tableNameOne;
    }

    public String getxColumn() {
        return xColumn;
    }

    public void setxColumn(String xColumn) {
        this.xColumn = xColumn;
    }

    public String getyColumn() {
        return yColumn;
    }

    public void setyColumn(String yColumn) {
        this.yColumn = yColumn;
    }
    public String getTableNameTwo() {
        return tableNameTwo;
    }

    public void setTableNameTwo(String tableNameTwo) {
        this.tableNameTwo = tableNameTwo;
    }

    public String getCalculation() {
        return calculation;
    }

    public void setCalculation(String calculation) {
        this.calculation = calculation;
    }
}
