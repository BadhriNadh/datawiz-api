package com.groupten.datawiz.service;

import com.groupten.datawiz.protocol.DbInfoRequest;

import java.util.List;


public interface DbInfoService {

    List<String> getDatabases(DbInfoRequest conn);
    List<String> getTables(DbInfoRequest conn);
    List<String> getColumns(DbInfoRequest conn);
    List<String> getIntegerColumns(DbInfoRequest conn);



}
