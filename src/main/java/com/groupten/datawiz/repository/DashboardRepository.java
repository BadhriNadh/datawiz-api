package com.groupten.datawiz.repository;

import com.groupten.datawiz.model.Dashboard;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;

import java.util.List;
import java.util.Optional;

public interface DashboardRepository extends JpaRepository<Dashboard, Integer> {

    Optional<Page<Dashboard>> findByUserId(Integer id, Pageable pageable);
}
