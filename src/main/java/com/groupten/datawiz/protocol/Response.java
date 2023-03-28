package com.groupten.datawiz.protocol;

import com.fasterxml.jackson.annotation.JsonInclude;

public class Response {

    private Object data;
    private int status;
    private String message;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Integer totalPages;

    public Response(Object data, int status, String message) {
        this.data = data;
        this.status = status;
        this.message = message;
    }

    public Response(Object data, int status, String message, Integer totalPages) {
        this.data = data;
        this.status = status;
        this.message = message;
        this.totalPages = totalPages;
    }

    public Object getData() {
        return data;
    }

    public void setData(Object data) {
        this.data = data;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Integer getTotalPages() {
        return totalPages;
    }

    public void setTotalPages(Integer totalPages) {
        this.totalPages = totalPages;
    }
}
