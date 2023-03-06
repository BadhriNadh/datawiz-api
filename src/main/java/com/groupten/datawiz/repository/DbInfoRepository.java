package com.groupten.datawiz.repository;

import com.groupten.datawiz.model.UserDbInfo;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;

public interface DbInfoRepository {
    List<String>  getDatabases(UserDbInfo dbInfo,JdbcTemplate jdbcTemplate);
    List<String>  getTables(UserDbInfo dbInfo,JdbcTemplate jdbcTemplate);
    List<String>  getColumns(UserDbInfo dbInfo,JdbcTemplate jdbcTemplate);
}
