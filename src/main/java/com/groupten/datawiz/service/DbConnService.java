package com.groupten.datawiz.service;
import com.groupten.datawiz.model.DbConn;
import java.util.*;

public interface DbConnService {

    DbConn saveConn(DbConn dbConn);

    DbConn editConn(DbConn dbConn);

    DbConn getConnById(int id);

    DbConn deleteConnById(int id);

    List<DbConn> getAllConnByUserId(int user_id);

    List<DbConn> findDbConnById(int id);

    Boolean testConn(DbConn dbConn);

}
