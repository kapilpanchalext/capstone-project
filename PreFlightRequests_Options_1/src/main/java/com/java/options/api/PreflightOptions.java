package com.java.options.api;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping(path = "/api/v1")
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class PreflightOptions {

	@GetMapping(path = "/helloworld")
	public ResponseEntity<String> getHelloWorld(){
		return ResponseEntity
					.status(HttpStatus.OK)
					.body("Helloworld Preflight-Options Request");
	}
	
//	@RequestMapping(path = "/helloworld", method = RequestMethod.OPTIONS)
//	public void handlePreflight(HttpServletResponse response) {
//		response.setHeader("Access-Control-Allow-Origin", "*");
//        response.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
//        response.setHeader("Access-Control-Allow-Headers", "Content-Type");
//        response.setStatus(HttpServletResponse.SC_OK);
//	}
}
