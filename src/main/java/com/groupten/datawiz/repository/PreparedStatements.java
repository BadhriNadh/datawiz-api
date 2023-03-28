package com.groupten.datawiz.repository;

import org.springframework.stereotype.Component;

@Component
public class PreparedStatements {

    public String getQueryForOneColumn(String schemaName, String tableName, String column){
         return "SELECT "+column+" FROM "+schemaName+"."+tableName;
    }

    public String getQueryForTwoColumn(String schemaName,String tableName, String xColumn, String yColumn, String calType){
        return "SELECT "+xColumn+","+calType+"("+yColumn+") FROM "+schemaName+"."+tableName + " GROUP BY "+ xColumn;
    }

    public String getQueryForRelatedTablesJoin(
            String schemaName,
            String tableNameOne,
            String tableNameTwo,
            String xColumnName,
            String yColumnName,
            String relationColumnTableOne,
            String relationColumnTableTwo,
            String  calType
    ){
        return "SELECT " +xColumnName+", "+calType+"("+yColumnName+
                ") FROM " +schemaName+"."+ tableNameOne +
                " JOIN " +schemaName+"."+ tableNameTwo +
                " ON " + tableNameOne + "." + relationColumnTableOne + " = " + tableNameTwo + "." + relationColumnTableTwo+
                " GROUP BY " + xColumnName;

    }


    public String testConnection(){
        return "SELECT 1";
    }

    // TODO can do better change CONSTRAINT_SCHEMA to * and use mapper
    public String getTableRelations(String tableNameOne, String tableNameTwo){
        return "SELECT * " +
                "FROM INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS " +
                "WHERE TABLE_NAME ='"+tableNameOne+"' AND REFERENCED_TABLE_NAME ='" + tableNameTwo+"'";
    }

    public String getRelatedColumns(String schemaName, String tableName, String tableNameReference){
        return "SELECT COLUMN_NAME, REFERENCED_COLUMN_NAME " +
                "FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE  " +
                "WHERE CONSTRAINT_SCHEMA = '"+schemaName+"' AND TABLE_NAME ='"+tableName+
                "' AND REFERENCED_TABLE_NAME ='" +tableNameReference+"'";
    }
}
