package com.groupten.datawiz.repository;

import com.groupten.datawiz.model.Visualization;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.sql.Timestamp;
import java.util.List;

public interface VisualizationRepository extends JpaRepository<Visualization, Integer> {

    Page<Visualization> findByConnectionIdAndDeletedAt(Integer connectionID, Timestamp deletedAt, Pageable pageable);

    @Modifying
    @Query("update Visualization v set v.deletedAt = :value where v.visualizationId = :id")
    void updateDeletedAtTime(@Param("id") int id, @Param("value") Timestamp value);

    List<Visualization> findByUserId(Integer userId);
    List<Visualization> findByUserIdAndSchemaName(Integer userId,String schemaName);

}
