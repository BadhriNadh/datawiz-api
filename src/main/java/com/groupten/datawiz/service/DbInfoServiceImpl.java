package com.groupten.datawiz.service;

import com.groupten.datawiz.config.DbConfig;
import com.groupten.datawiz.model.DbConn;
import com.groupten.datawiz.protocol.DbInfoRequest;
import com.groupten.datawiz.repository.DbInfoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
public class DbInfoServiceImpl implements  DbInfoService{


    @Autowired
    DbConnService connService;

    @Autowired
    DbConfig dbConfig;

    @Autowired
    DbInfoRepository dbInfoRepository;

    @Override
    public List<String> getDatabases(DbInfoRequest dbInfo){
        DbConn conn = connService.getConnById(dbInfo.getConnectionId());
        var dataSource =  dbConfig.DbConnection(conn);
        var value = dbInfoRepository.getDatabases(dbInfo,new JdbcTemplate(dataSource));
        dataSource.close();
        return value;
    }

    @Override
    public List<String> getTables(DbInfoRequest dbInfo){

        DbConn conn = connService.getConnById(dbInfo.getConnectionId());

        var dataSource =  dbConfig.DbConnection(conn);
        var value = dbInfoRepository.getTables(dbInfo,new JdbcTemplate(dataSource));
        dataSource.close();
        return value;
    }

    @Override
    public List<String> getColumns(DbInfoRequest dbInfo){
        DbConn conn = connService.getConnById(dbInfo.getConnectionId());

        var dataSource =  dbConfig.DbConnection(conn);
        var value =  dbInfoRepository.getColumns(dbInfo,new JdbcTemplate(dataSource));
        dataSource.close();
        return value;
    }
    @Override
    public List<String> getIntegerColumns(DbInfoRequest dbInfo){
        DbConn conn = connService.getConnById(dbInfo.getConnectionId());

        var dataSource =  dbConfig.DbConnection(conn);
        var value =  dbInfoRepository.getIntegerColumns(dbInfo,new JdbcTemplate(dataSource));
        dataSource.close();
        return value;
    }


}
