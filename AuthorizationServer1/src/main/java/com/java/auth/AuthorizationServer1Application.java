package com.java.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
@EnableWebSecurity(debug = true)
public class AuthorizationServer1Application {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationServer1Application.class, args);
	}

}
