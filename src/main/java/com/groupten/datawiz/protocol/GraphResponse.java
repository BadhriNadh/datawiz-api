package com.groupten.datawiz.protocol;

import java.util.List;

public class GraphResponse {

    private List<Object> x;
    private List<Object> y;
    public GraphResponse(List<Object> x, List<Object> y) {
        this.x = x;
        this.y = y;
    }

    public List<Object> getX() {
        return x;
    }

    public void setX(List<Object> x) {
        this.x = x;
    }

    public List<Object> getY() {
        return y;
    }

    public void setY(List<Object> y) {
        this.y = y;
    }
}
