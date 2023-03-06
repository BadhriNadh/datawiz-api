package com.groupten.datawiz.service;

import com.groupten.datawiz.model.DbConn;
import com.groupten.datawiz.model.UserDbInfo;

import java.util.List;


public interface DbInfoService {

    List<String> getDatabases(UserDbInfo conn);
    List<String> getTables(UserDbInfo conn);
    List<String> getColumns(UserDbInfo conn);


}
