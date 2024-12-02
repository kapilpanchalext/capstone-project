package com.java.oauth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.java.oauth.model.Role;


public interface RolesRepository extends JpaRepository<Role, Long>{

	@Query(value = "SELECT * FROM roles WHERE name = :name", nativeQuery = true)
	Optional<Role> getByName(@Param("name") String name);
}
