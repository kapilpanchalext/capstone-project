package com.java.registration.api;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.java.registration.model.Role;
import com.java.registration.model.Student;
import com.java.registration.repository.RolesRepository;
import com.java.registration.repository.StudentRepository;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class StudentController {
	
	private final StudentRepository repo;
	private final RolesRepository rolesRepo;
	private final PasswordEncoder passwordEncoder;

	@PostMapping(path = "/register-student")
	public ResponseEntity<String> registerStudent(@RequestBody Student student){
		System.err.println("Student: " + student);
		try {
			String hashPwd = passwordEncoder.encode(student.getPassword());
			student.setPassword(hashPwd);
			Student savedStudent = repo.save(student);
			
			if(savedStudent.getStudent_id() > 0) {
				return ResponseEntity
						.status(HttpStatus.CREATED)
						.body("User Registered Successfully!");
			} else {
				return ResponseEntity
						.status(HttpStatus.BAD_REQUEST)
						.body("Bad Request");
			}
		} catch(Exception e) {
			return ResponseEntity
					.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("An Exception Occurred: " + e.getMessage());
		}
	}
	
	@PostMapping(path = "/register-role")
	public ResponseEntity<String> registerNewRole(@RequestBody Role role){
		try {
			Role savedRole = rolesRepo.save(role);
			
			if(savedRole.getRole_id() > 0) {
				return ResponseEntity
						.status(HttpStatus.CREATED)
						.body("New Role Created Successfully!");
			} else {
				return ResponseEntity
						.status(HttpStatus.BAD_REQUEST)
						.body("Bad Request");
			}
		} catch(Exception e) {
			return ResponseEntity
					.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("An Exception Occurred: " + e.getMessage());
		}
	}
	
	@PostMapping(path = "/assign-roles")
	public ResponseEntity<String> assignRoleToStudent(@RequestParam String role, 
														@RequestParam String email){
		
		// Fetch the student by ID
	    Student student = repo.findByEmail(email)
	                          .orElseThrow(() -> new IllegalArgumentException("Student not found"));

	    // Create a new role or find an existing one
	    Role studentRole = rolesRepo
	    					.getByName(role)
	    					.orElse(Role.builder().name(role).build());
	    Set<Student> roleSet = new HashSet<>();
	    roleSet.add(student);
	    // Set the relationship between student and role
	    studentRole.setStudent(roleSet);

	    // Add the role to the student's roles set
	    if (student.getRoles() == null) {
	        student.setRoles(new HashSet<>());
	    }
	    student.getRoles().add(studentRole);

	    // Save the role and student (cascading will handle saving both if configured)
	    rolesRepo.save(studentRole);
	    
	    System.err.println(repo.findByEmail(email));
		
		return ResponseEntity
				.status(HttpStatus.OK)
				.body("Role Assigned To Student");
	}
	
	@GetMapping(path = "/get-student-by-email")
	public ResponseEntity<List<Student>> getStudentByEmail(){
		
		List<Student> studentsList = repo.findAll();
		
		return ResponseEntity
				.status(HttpStatus.OK)
				.body(studentsList);
	}
	
	@GetMapping(path = "/student")
	public ResponseEntity<String> getStudentDetails(Authentication authentication){
		Optional<Student> optionalStudent = repo.findByEmail(authentication.getName());
		System.err.println("Authentication: " + authentication);
		return ResponseEntity.status(HttpStatus.OK).body(optionalStudent.get().toString());
	}
}
