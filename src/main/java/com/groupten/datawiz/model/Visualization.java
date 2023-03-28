package com.groupten.datawiz.model;
import jakarta.persistence.*;

import java.sql.Timestamp;

@Entity
@Table(name = "visualizations")
public class Visualization{

    @Id
    @Column(name = "visualization_id")
    @GeneratedValue(strategy = GenerationType.AUTO)
    private int visualizationId;

    @Column(name = "connection_id")
    private int connectionId;

    @Column(name = "schemaName")
    private String schemaName;

    @Column(name = "user_id")
    private int userId;

    @Column(name = "visualization_name")
    private String name;

    @Column(name = "chart_type")
    private String chartType;

    @Column(name = "x_table")
    private String xTable;

    @Column(name = "x_attribute")
    private String xAttribute;

    @Column(name = "y_table")
    private String yTable;

    @Column(name = "y_attribute")
    private String yAttribute;

    private String calculation;

    @Column(name = "updated_at")
    private Timestamp updatedAt;

    @Column(name = "deleted_at")
    private Timestamp deletedAt;

    public Visualization(){}

    public Visualization(int connectionId,String schemaName, int userId, String name, String chartType, String xTable, String xAttribute, String yTable, String yAttribute, String calculation, Timestamp updatedAt) {
        this.connectionId = connectionId;
        this.schemaName=schemaName;
        this.userId = userId;
        this.name = name;
        this.chartType = chartType;
        this.xTable = xTable;
        this.xAttribute = xAttribute;
        this.yTable = yTable;
        this.yAttribute = yAttribute;
        this.calculation = calculation;
        this.updatedAt = updatedAt;
    }

    public Visualization(int visualizationId,int connectionId,String schemaName, int userId, String name, String chartType, String xTable, String xAttribute, String yTable, String yAttribute, String calculation, Timestamp updatedAt) {
        this.visualizationId = visualizationId;
        this.connectionId = connectionId;
        this.schemaName=schemaName;
        this.userId = userId;
        this.name = name;
        this.chartType = chartType;
        this.xTable = xTable;
        this.xAttribute = xAttribute;
        this.yTable = yTable;
        this.yAttribute = yAttribute;
        this.calculation = calculation;
        this.updatedAt = updatedAt;
    }
    public String getSchemaName() {
        return schemaName;
    }

    public void setSchemaName(String schemaName) {
        this.schemaName = schemaName;
    }

    public int getVisualizationId() {
        return visualizationId;
    }

    public void setVisualizationId(int visualizationId) {
        this.visualizationId = visualizationId;
    }

    public int getConnectionId() {
        return connectionId;
    }

    public void setConnectionId(int connectionId) {
        this.connectionId = connectionId;
    }

    public int getUserId() {
        return userId;
    }

    public void setUserId(int userId) {
        this.userId = userId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getChartType() {
        return chartType;
    }

    public void setChartType(String chartType) {
        this.chartType = chartType;
    }

    public String getxTable() {
        return xTable;
    }

    public void setxTable(String xTable) {
        this.xTable = xTable;
    }

    public String getxAttribute() {
        return xAttribute;
    }

    public void setxAttribute(String xAttribute) {
        this.xAttribute = xAttribute;
    }

    public String getyTable() {
        return yTable;
    }

    public void setyTable(String yTable) {
        this.yTable = yTable;
    }

    public String getyAttribute() {
        return yAttribute;
    }

    public void setyAttribute(String yAttribute) {
        this.yAttribute = yAttribute;
    }

    public Timestamp getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Timestamp updatedAt) {
        this.updatedAt = updatedAt;
    }

    public Timestamp getDeletedAt() {
        return deletedAt;
    }

    public void setDeletedAt(Timestamp deletedAt) {
        this.deletedAt = deletedAt;
    }

    public String getCalculation() {
        return calculation;
    }

    public void setCalculation(String calculation) {
        this.calculation = calculation;
    }
}
