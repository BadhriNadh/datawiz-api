package com.groupten.datawiz.repository;

import org.springframework.stereotype.Service;

@Service
public class PreparedStatements {

    public String barGraphCountQuery(String tableName, String xColumn, String yColumn){
         return "SELECT "+xColumn+","+yColumn+" FROM "+tableName;
    }

    public String testConnection(){
        return "SELECT 1";
    }
}
