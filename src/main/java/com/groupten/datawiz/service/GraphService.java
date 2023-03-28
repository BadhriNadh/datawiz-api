package com.groupten.datawiz.service;

import com.groupten.datawiz.protocol.GraphRequest;
import com.groupten.datawiz.protocol.GraphResponse;

import java.util.List;

public interface GraphService {
    GraphResponse getGraphValues(GraphRequest graphRequest);
}
