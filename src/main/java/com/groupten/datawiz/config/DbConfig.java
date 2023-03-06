package com.groupten.datawiz.config;

import com.groupten.datawiz.model.DbConn;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.stereotype.Component;

@Component
public class DbConfig {

    public HikariDataSource DbConnection(DbConn dbConn) {
        HikariDataSource dataSource = new HikariDataSource();
        dataSource.setJdbcUrl(dbConn.getUrl());
        dataSource.setUsername(dbConn.getDbUsername());
        dataSource.setPassword(dbConn.getDbPassword());
        return dataSource;
    }

    // TODO try beans
}
