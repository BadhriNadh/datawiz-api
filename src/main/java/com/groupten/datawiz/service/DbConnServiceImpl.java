package com.groupten.datawiz.service;
import com.groupten.datawiz.config.DbConfig;
import com.groupten.datawiz.model.DbConn;
import com.groupten.datawiz.repository.ConnectionRepository;
import com.groupten.datawiz.repository.GraphRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.text.SimpleDateFormat;
import java.util.*;

@Service
@Transactional
public class DbConnServiceImpl implements DbConnService{

    @Autowired
    ConnectionRepository connectionRepository;

    @Autowired
    GraphRepository graphRepository;

    @Autowired
    DbConfig dbConfig;

    @Override
    public DbConn saveConn(DbConn dbConn){
        DbConn conn = new DbConn(dbConn.getUserId(), dbConn.getUrl(), dbConn.getName(), dbConn.getDbUsername(), dbConn.getDbPassword());
        return connectionRepository.save(conn);
    }


    /*
    Body should provide existing connection_id and edited fields like so:
    {
    "id": 252,
    "userId": 52,
    "name": "updated",
    "url": "updated",
    "db_username": "updated",
    "db_password": "updated"
    }
     */
    @Override
    public DbConn editConn(DbConn dbConn){
        DbConn originalConn = getConnById(dbConn.getId());
        originalConn.setUrl(dbConn.getUrl());
        originalConn.setName(dbConn.getName());
        originalConn.setDbUsername(dbConn.getDbUsername());
        originalConn.setDbPassword(dbConn.getDbPassword());
        String created_at = getConnById(dbConn.getId()).getCreatedAt();
        SimpleDateFormat dateFormat = new SimpleDateFormat("YYYY-MM-DD hh:mm:ss");
        Calendar cal = Calendar.getInstance();
        String updated_at = dateFormat.format(cal.getTime());
        originalConn.setUpdatedAt(updated_at);
        return connectionRepository.save(originalConn);
    }


    @Override
    public DbConn getConnById(int id){
        DbConn conn = connectionRepository.findById(id).orElse(null);
        return conn;
    }

    @Override
    public List<DbConn> findDbConnById(int id){
        DbConn conn = connectionRepository.findById(id).orElse(null);
        List<DbConn> resConn = new ArrayList<>();
        if(conn==null){
            return resConn;
        }
        resConn.add(conn);
        return resConn;
    }

    @Override
    public List<DbConn> getAllConnByUserId(int userId){
        List<DbConn> allConns = connectionRepository.findByUserId(userId);
        if(allConns.isEmpty()){
            return new ArrayList<>();
        }
        else{
            return allConns;
        }
    }

    @Override
    public DbConn deleteConnById(int id){
        DbConn conn = getConnById(id);
        connectionRepository.deleteById(id);
        return conn;
    }

    @Override
    public Boolean testConn(DbConn dbConn){
        var dataSource =  dbConfig.DbConnection(dbConn);
        var value = graphRepository.testConnection(new JdbcTemplate(dataSource));
        dataSource.close();
        return value;
    }
}
