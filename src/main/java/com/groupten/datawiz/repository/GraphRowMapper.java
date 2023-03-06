package com.groupten.datawiz.repository;

import com.groupten.datawiz.model.Graph;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;

public class GraphRowMapper implements RowMapper<Graph> {

    @Override
    public Graph mapRow(ResultSet rs, int rowNum) throws SQLException {
        Graph graph = new Graph();
        graph.setX(rs.getObject(1));
        graph.setY(rs.getObject(2));
        return graph;
    }
}
