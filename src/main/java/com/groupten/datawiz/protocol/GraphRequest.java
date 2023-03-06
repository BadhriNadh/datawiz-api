package com.groupten.datawiz.protocol;

public class GraphRequest {

    private String tableName;
    private String xColumn;
    private String yColumn;
    private int connectionId;

    public int getConnectionId() {
        return connectionId;
    }

    public void setConnectionId(int connectionId) {
        this.connectionId = connectionId;
    }

    public String getTableName() {
        return tableName;
    }

    public void setTableName(String tableName) {
        this.tableName = tableName;
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
}
