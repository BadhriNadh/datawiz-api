package com.groupten.datawiz.repository;
import com.groupten.datawiz.model.DbConn;
import com.groupten.datawiz.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;
import java.util.*;

public interface ConnectionRepository extends CrudRepository<DbConn, Integer>{

    DbConn findDbConnById(int id);

    List<DbConn> findByUserId(int userId);

}
