package com.java.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
@EnableWebSecurity(debug = true)
public class AuthorizationServerLogin2Application {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationServerLogin2Application.class, args);
	}

}
