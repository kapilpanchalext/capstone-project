package com.java.oauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.DispatcherServlet;

@Configuration
public class WebConfig {

	@Bean
	DispatcherServlet dispatcherServlet() {
//		DispatcherServlet dispatcherServlet = new DispatcherServlet();
//		dispatcherServlet.setApplicationContext(null);
		return new CustomDispatcherServlet();
	}
}
