package com.java.oauth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.java.oauth.model.Student;


public interface StudentRepository extends JpaRepository<Student, Long>{

	Optional<Student> findByEmail(String email);
	Student findTopByOrderByIdDesc();
	
}
