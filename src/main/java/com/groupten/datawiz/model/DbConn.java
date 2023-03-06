package com.groupten.datawiz.model;

import jakarta.persistence.*;

import java.text.SimpleDateFormat;
import java.util.Calendar;

@Entity
@Table(name="connections")
public class DbConn {
    @Id
    @Column(name = "connection_id")
    @GeneratedValue(strategy = GenerationType.AUTO)
    private int id;

    @Column(name = "user_id")
    private int userId;

    private String name;

    private String url;

    @Column(name = "username")
    private String dbUsername;

    @Column(name = "password")
    private String dbPassword;

    private String createdAt;

    private String updatedAt;

    private String deletedAt;

    @Column(name = "status")
    private Boolean connStatus;

    public DbConn(){}

    public DbConn(int userId, String url, String name, String username, String password){
        this.userId = userId;
        this.url = url;
        this.name = name;
        dbUsername = username;
        dbPassword = password;
        SimpleDateFormat dateFormat = new SimpleDateFormat("YYYY-MM-DD hh:mm:ss");
        Calendar cal = Calendar.getInstance();
        createdAt = dateFormat.format(cal.getTime());
        updatedAt = null;
        deletedAt = null;
        connStatus = false;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getId() {
        return id;
    }

    public void setId(int connectionId) {
        this.id = connectionId;
    }

    public int getUserId() {
        return userId;
    }

    public void setUserId(int conn_user_id) {
        this.userId = conn_user_id;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getDbUsername() {
        return dbUsername;
    }

    public void setDbUsername(String dbUsername) {
        this.dbUsername = dbUsername;
    }

    public String getDbPassword() {
        return dbPassword;
    }

    public void setDbPassword(String dbPassword) {
        this.dbPassword = dbPassword;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    public String getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(String updatedAt) {
        this.updatedAt = updatedAt;
    }

    public String getDeletedAt() {
        return deletedAt;
    }

    public void setDeletedAt(String deletedAt) {
        this.deletedAt = deletedAt;
    }

    public boolean isConnStatus() {
        return connStatus;
    }

    public void setConnStatus(boolean connStatus) {
        this.connStatus = connStatus;
    }
}
