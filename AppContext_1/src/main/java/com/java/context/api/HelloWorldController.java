package com.java.context.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.DispatcherServlet;

@RestController
@RequestMapping(path = "/api/v1")
public class HelloWorldController {

	@Autowired
	private ApplicationContext context;
	
	@Autowired
	private DispatcherServlet servlet;
	
	@GetMapping(path = "/helloworld")
	public ResponseEntity<String> getHelloWorld(){
		
		System.err.println(context.getApplicationName());
		System.err.println(context.getDisplayName());
		System.err.println(context.getId());
		System.err.println(context.getEnvironment());
		System.err.println(context.getParent());
		System.err.println(context.getParentBeanFactory());
		
		System.err.println(servlet.getServletInfo());
		System.err.println(servlet.getServletName());
		System.err.println(servlet.getEnvironment());
		System.err.println(servlet.getNamespace());
		
		return ResponseEntity.status(HttpStatus.OK).body("HelloWorld Application Context");
	}
}
