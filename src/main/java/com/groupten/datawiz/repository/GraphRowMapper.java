package com.groupten.datawiz.repository;

import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;

public class GraphRowMapper implements RowMapper<GraphRow> {

    @Override
    public GraphRow mapRow(ResultSet rs, int rowNum) throws SQLException {
        GraphRow graphRow = new GraphRow();
        graphRow.setX(rs.getObject(1));
        graphRow.setY(rs.getObject(2));
        return graphRow;
    }
}
