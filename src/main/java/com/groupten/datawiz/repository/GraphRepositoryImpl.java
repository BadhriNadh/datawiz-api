package com.groupten.datawiz.repository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;

@Repository
public class GraphRepositoryImpl implements GraphRepository {

    @Autowired
    private PreparedStatements preparedStatements;

    @Override
    public Boolean testConnection(JdbcTemplate jdbcTemplate) {
        try {
            jdbcTemplate.queryForObject(preparedStatements.testConnection(), Integer.class);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    @Override
    public List<Object> getGraphValues(String schemaName,String tableName, String columnName, JdbcTemplate jdbcTemplate) {
        return jdbcTemplate.queryForList(preparedStatements.getQueryForOneColumn(schemaName,tableName,columnName),Object.class);
    }

    @Override
    public List<GraphRow> getGraphValuesSameTable(String schemaName, String tableName, String xColumnName, String yColumnName, String calType, JdbcTemplate jdbcTemplate) {

        return jdbcTemplate.query(
                preparedStatements.getQueryForTwoColumn(
                        schemaName,
                        tableName,
                        xColumnName,
                        yColumnName,
                        calType
                ),
                new GraphRowMapper()
        );
    }

    @Override
    public List<GraphRow> getGraphValuesRelatedTables(
            String schemaName,
            String tableNameOne,
            String tableNameTwo,
            String xColumnName,
            String yColumnName,
            String relationColumnTableOne,
            String relationColumnTableTwo,
            String calType,
            JdbcTemplate jdbcTemplate
    ){
        return jdbcTemplate.query(
                preparedStatements.getQueryForRelatedTablesJoin(
                        schemaName,
                        tableNameOne,
                        tableNameTwo,
                        xColumnName,
                        yColumnName,
                        relationColumnTableOne,
                        relationColumnTableTwo,
                        calType
                ),
                new GraphRowMapper()
        );
    }

    @Override
    public Boolean checkIfRelated(String tableNameOne, String tableNameTwo, JdbcTemplate jdbcTemplate) {
        return !jdbcTemplate.queryForList(preparedStatements.getTableRelations(tableNameOne,tableNameTwo)).isEmpty();
    }

    @Override
    public List<Map<String, Object>> getRelatedColumn(String schemaName, String tableName, String tableNameReference, JdbcTemplate jdbcTemplate) {
        return jdbcTemplate.queryForList(preparedStatements.getRelatedColumns(schemaName,tableName,tableNameReference));
    }

}
