package com.groupten.datawiz.repository;

import com.groupten.datawiz.model.UserDbInfo;
import org.springframework.context.annotation.Lazy;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Lazy
@Repository
public class DbInfoRepositoryImpl implements DbInfoRepository{


    @Override
    public List<String> getDatabases(UserDbInfo dbInfo, JdbcTemplate jdbcTemplate){

        return jdbcTemplate.query("show databases;",new DbInfoRowMapper());
    }

    @Override
    public List<String> getTables(UserDbInfo dbInfo, JdbcTemplate jdbcTemplate){

        return jdbcTemplate.query("show tables from "+dbInfo.getDatabase()+";",new DbInfoRowMapper());
    }

    @Override
    public List<String> getColumns(UserDbInfo dbInfo, JdbcTemplate jdbcTemplate){

        return jdbcTemplate.query("show columns from "+dbInfo.getTable()+" in "+dbInfo.getDatabase()+" ;",new DbInfoRowMapper());
    }


}
