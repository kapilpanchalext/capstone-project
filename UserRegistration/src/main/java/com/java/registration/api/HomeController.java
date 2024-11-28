package com.java.registration.api;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/")
public class HomeController {
	
	@GetMapping(path = "/home")
	public ResponseEntity<String> getHelloWorld() {
		
		return ResponseEntity
					.status(HttpStatus.OK)
					.body("Home: ");
	}
}
