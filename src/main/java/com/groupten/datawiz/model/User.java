package com.groupten.datawiz.model;

import jakarta.persistence.*;


@Entity
@Table(name = "user")
public class User {

    @Id
    @Column(name = "user_id")
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long userId;

    private String username;

    private String password;

    @Column(name = "user")
    private String profileName;

    public User() {}

    public User(String profileName, String username) {
        this.profileName = profileName;
        this.username = username;
    }

    public User(String profileName, String username, String password) {
        this.profileName = profileName;
        this.username = username;
        this.password = password;
    }

    public long getUserId() {
        return userId;
    }

    public void setUserId(long userId) {
        this.userId = userId;
    }

    public String getProfileName() {
        return profileName;
    }

    public void setProfileName(String profileName) {
        this.profileName = profileName;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
