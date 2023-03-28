package com.groupten.datawiz.service;

import com.groupten.datawiz.config.DbConfig;
import com.groupten.datawiz.model.DbConn;
import com.groupten.datawiz.repository.GraphRow;
import com.groupten.datawiz.protocol.GraphRequest;
import com.groupten.datawiz.protocol.GraphResponse;
import com.groupten.datawiz.repository.GraphRepository;
import com.groupten.datawiz.repository.ConnectionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;

@Service
public class GraphServiceImpl implements GraphService {

    @Autowired
    GraphRepository graphRepository;
    @Autowired
    ConnectionRepository connectRepository;
    @Autowired
    DbConfig dbConfig;

    @Override
    public GraphResponse getGraphValues(GraphRequest graphRequest) {

        GraphResponse result ;
        DbConn dbConn= connectRepository.findDbConnById(graphRequest.getConnectionId());
        var dataSource =  dbConfig.DbConnection(dbConn);
        var jdbcTemplate = new JdbcTemplate(dataSource);

        if(graphRequest.getTableNameOne().equals(graphRequest.getTableNameTwo())){
            result = getFromOneTable(graphRequest, jdbcTemplate);
        }else{
            result = getFromTwoTables(graphRequest, jdbcTemplate);
        }

        dataSource.close();

        return result;
    }

    private GraphResponse getFromOneTable(GraphRequest graphRequest, JdbcTemplate jdbcTemplate){
        var values =graphRepository.getGraphValuesSameTable(
                graphRequest.getSchemaName(),
                graphRequest.getTableNameOne(),
                graphRequest.getxColumn(),
                graphRequest.getyColumn(),
                graphRequest.getCalculation(),
                jdbcTemplate
        );

        var valuesFilter = values.stream().filter(s -> s.getX() != null ).filter(s -> s.getY() != null ).toList();
        List<Object> xList = valuesFilter.stream().map(GraphRow::getX).toList();
        List<Object> yList = valuesFilter.stream().map(GraphRow::getY).toList();
        return new GraphResponse(xList, yList);
    }

    private GraphResponse getFromTwoTablesNoRelation(GraphRequest graphRequest, JdbcTemplate jdbcTemplate){
        var xValues =graphRepository
                .getGraphValues(graphRequest.getSchemaName(),graphRequest.getTableNameOne(),graphRequest.getxColumn(), jdbcTemplate)
                .stream().filter(Objects::nonNull).toList();
        var yValues =graphRepository
                .getGraphValues(graphRequest.getSchemaName(), graphRequest.getTableNameTwo(),graphRequest.getyColumn(), jdbcTemplate)
                .stream().filter(Objects::nonNull).toList();

        return new GraphResponse(xValues, yValues);
    }

    private GraphResponse getFromTwoTablesRelation(GraphRequest graphRequest,String table, String refTable, JdbcTemplate jdbcTemplate) {
        var refColumn = graphRepository.getRelatedColumn(graphRequest.getSchemaName(), table, refTable, jdbcTemplate);

        var values = graphRepository.getGraphValuesRelatedTables(
                graphRequest.getSchemaName(),
                table,
                refTable,
                graphRequest.getxColumn(),
                graphRequest.getyColumn(),
                refColumn.get(0).get("COLUMN_NAME").toString(),
                refColumn.get(0).get("REFERENCED_COLUMN_NAME").toString(),
                graphRequest.getCalculation(),
                jdbcTemplate
        );

        var valuesFilter = values.stream().filter(s -> s.getX() != null ).filter(s -> s.getY() != null ).toList();
        List<Object> xList = valuesFilter.stream().map(GraphRow::getX).toList();
        List<Object> yList = valuesFilter.stream().map(GraphRow::getY).toList();
        return new GraphResponse(xList, yList);
    }

    private GraphResponse getFromTwoTables(GraphRequest graphRequest, JdbcTemplate jdbcTemplate){
        if(graphRepository.checkIfRelated(graphRequest.getTableNameOne() ,graphRequest.getTableNameTwo(), jdbcTemplate)){
            var table = graphRequest.getTableNameOne();
            var refTable = graphRequest.getTableNameTwo();
            return getFromTwoTablesRelation(graphRequest, table, refTable, jdbcTemplate);
        } else if (graphRepository.checkIfRelated(graphRequest.getTableNameTwo(), graphRequest.getTableNameOne(), jdbcTemplate)){
            var table = graphRequest.getTableNameTwo();
            var refTable = graphRequest.getTableNameOne();
            return getFromTwoTablesRelation(graphRequest, table, refTable, jdbcTemplate);
        } else {
            return getFromTwoTablesNoRelation(graphRequest, jdbcTemplate);
        }
    }
}
