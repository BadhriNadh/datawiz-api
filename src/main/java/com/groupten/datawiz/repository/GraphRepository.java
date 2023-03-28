package com.groupten.datawiz.repository;

import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;

public interface GraphRepository {

    List<Object> getGraphValues(String schemaName,String tableName, String columnName, JdbcTemplate jdbcTemplate);

    Boolean testConnection(JdbcTemplate jdbcTemplate);

    List<GraphRow> getGraphValuesSameTable(String schemaName, String tableName, String xColumnName, String yColumnName, String calType, JdbcTemplate jdbcTemplate);

    List<GraphRow> getGraphValuesRelatedTables(
            String schemaName,
            String tableNameOne,
            String tableNameTwo,
            String xColumnName,
            String yColumnName,
            String relationColumnTableOne,
            String relationColumnTableTwo,
            String calType,
            JdbcTemplate jdbcTemplate
    );

    Boolean checkIfRelated(String tableNameOne, String tableNameTwo, JdbcTemplate jdbcTemplate);

    List<Map<String, Object>> getRelatedColumn(String schemaName, String tableName, String tableNameReference, JdbcTemplate jdbcTemplate);
}
