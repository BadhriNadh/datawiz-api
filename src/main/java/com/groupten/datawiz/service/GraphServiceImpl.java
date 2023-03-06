package com.groupten.datawiz.service;

import com.groupten.datawiz.config.DbConfig;
import com.groupten.datawiz.model.DbConn;
import com.groupten.datawiz.model.Graph;
import com.groupten.datawiz.protocol.GraphRequest;
import com.groupten.datawiz.protocol.GraphResponse;
import com.groupten.datawiz.repository.GraphRepository;
import com.groupten.datawiz.repository.ConnectionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.sql.SQLException;
import java.util.List;

@Service
public class GraphServiceImpl implements GraphService {

    @Autowired
    GraphRepository graphRepository;
    @Autowired
    ConnectionRepository connectRepository;
    @Autowired
    DbConfig dbConfig;

    public GraphResponse getValues(GraphRequest graphRequest) {
        DbConn dbConn= connectRepository.findDbConnById(graphRequest.getConnectionId());
        var dataSource =  dbConfig.DbConnection(dbConn);
        var values =graphRepository.getIntIntValues(graphRequest, new JdbcTemplate(dataSource));
        dataSource.close();

        var valuesFilter = values.stream().filter(s -> s.getX() != null ).filter(s -> s.getY() != null ).toList();
        List<Object> xList = valuesFilter.stream().map(Graph::getX).toList();
        List<Object> yList = valuesFilter.stream().map(Graph::getY).toList();
        return new GraphResponse(xList, yList);
    }
}
