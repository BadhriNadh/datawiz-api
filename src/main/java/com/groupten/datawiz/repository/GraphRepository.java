package com.groupten.datawiz.repository;

import com.groupten.datawiz.model.*;
import com.groupten.datawiz.protocol.GraphRequest;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;

public interface GraphRepository {

    List<Graph> getIntIntValues(GraphRequest graphRequest, JdbcTemplate jdbcTemplate);


    Boolean testConnection(JdbcTemplate jdbcTemplate);




}
