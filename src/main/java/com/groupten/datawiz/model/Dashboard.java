package com.groupten.datawiz.model;
import jakarta.persistence.*;


@Entity
@Table(name = "dashboard")
public class Dashboard {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Integer dashboardId;

    private Integer userId;

    private String name;

    private Integer visualOneId;

    private Integer visualTwoId;

    private Integer visualThreeId;

    private Integer visualFourId;


    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Integer getDashboardId() {
        return dashboardId;
    }

    public void setDashboardId(Integer dashboardId) {
        this.dashboardId = dashboardId;
    }

    public Integer getUserId() {
        return userId;
    }

    public void setUserId(Integer userId) {
        this.userId = userId;
    }

    public Integer getVisualOneId() {
        return visualOneId;
    }

    public void setVisualOneId(Integer visualOneId) {
        this.visualOneId = visualOneId;
    }

    public Integer getVisualTwoId() {
        return visualTwoId;
    }

    public void setVisualTwoId(Integer visualTwoId) {
        this.visualTwoId = visualTwoId;
    }

    public Integer getVisualThreeId() {
        return visualThreeId;
    }

    public void setVisualThreeId(Integer visualThreeId) {
        this.visualThreeId = visualThreeId;
    }

    public Integer getVisualFourId() {
        return visualFourId;
    }

    public void setVisualFourId(Integer visualFourId) {
        this.visualFourId = visualFourId;
    }
}
