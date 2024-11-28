package com.java.registration.api;

import java.util.List;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.java.registration.model.Student;
import com.java.registration.repository.StudentRepository;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class StudentController {
	
	private final StudentRepository repo;
	
	@GetMapping(path = "/get-students-list-by-email")
	public ResponseEntity<List<Student>> getStudentByEmail(){
		List<Student> studentsList = repo.findAll();
		
		return ResponseEntity
				.status(HttpStatus.OK)
				.body(studentsList);
	}
	
	@GetMapping(path = "/get-logged-student-details")
	public ResponseEntity<String> getStudentDetails(Authentication authentication){
		Optional<Student> optionalStudent = repo.findByEmail(authentication.getName());
		return ResponseEntity.status(HttpStatus.OK).body(optionalStudent.get().toString());
	}
	
	@GetMapping(path = "/get-student-count")
	public ResponseEntity<Long> getStudentCount(){
		long studentCount = repo.count();
		return ResponseEntity.status(HttpStatus.OK).body(studentCount);
	}
}
