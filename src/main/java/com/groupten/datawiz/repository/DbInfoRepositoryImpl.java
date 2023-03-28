package com.groupten.datawiz.repository;

import com.groupten.datawiz.protocol.DbInfoRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.Arrays;
import java.util.List;

@Repository
public class DbInfoRepositoryImpl implements DbInfoRepository{


    @Override
    public List<String> getDatabases(DbInfoRequest dbInfo, JdbcTemplate jdbcTemplate){

        return jdbcTemplate.query("show databases;",new DbInfoRowMapper());
    }

    @Override
    public List<String> getTables(DbInfoRequest dbInfo, JdbcTemplate jdbcTemplate){

        return jdbcTemplate.query("show tables from "+dbInfo.getSchema()+";",new DbInfoRowMapper());
    }

    @Override
    public List<String> getColumns(DbInfoRequest dbInfo, JdbcTemplate jdbcTemplate){

        return jdbcTemplate.query("show columns from "+dbInfo.getTable()+" in "+dbInfo.getSchema()+" ;",new DbInfoRowMapper());
    }

    @Override
    public List<String> getIntegerColumns(DbInfoRequest dbInfo, JdbcTemplate jdbcTemplate){
        String query="select column_Name " +
                "from INFORMATION_SCHEMA.COLUMNS " +
                "where TABLE_NAME='"+dbInfo.getTable()+"' AND TABLE_SCHEMA = '"+dbInfo.getSchema()+"' AND (DATA_TYPE = 'int' " +
                "or DATA_TYPE = 'smallint' or DATA_TYPE = 'decimal' or DATA_TYPE = 'float' " +
                "or DATA_TYPE = 'double' or DATA_TYPE = 'bigint' or DATA_TYPE = 'int')  ;";
        return jdbcTemplate.query(query,new DbInfoRowMapper());
    }


}
