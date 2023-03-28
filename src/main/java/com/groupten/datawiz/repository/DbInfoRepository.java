package com.groupten.datawiz.repository;

import com.groupten.datawiz.protocol.DbInfoRequest;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;

public interface DbInfoRepository {
    List<String>  getDatabases(DbInfoRequest dbInfo, JdbcTemplate jdbcTemplate);
    List<String>  getTables(DbInfoRequest dbInfo, JdbcTemplate jdbcTemplate);
    List<String>  getColumns(DbInfoRequest dbInfo, JdbcTemplate jdbcTemplate);
    List<String>  getIntegerColumns(DbInfoRequest dbInfo, JdbcTemplate jdbcTemplate);
}
