package com.java.oauth.config;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private final RequestCache requestCache = new HttpSessionRequestCache();
	
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		
		System.err.println("JWT AUTHENTICATION SUCCESS HANDLER: " + requestCache);
		SavedRequest savedRequest = requestCache.getRequest(request, response);
		System.err.println("JWT AUTHENTICATION SUCCESS HANDLER: " + savedRequest);
		
	    if (savedRequest != null) {
	            String targetUrl = savedRequest.getRedirectUrl();
	            requestCache.removeRequest(request, response);
	            response.sendRedirect(targetUrl); // Redirect to the saved URL
         } else {
	            response.sendRedirect("/default"); // Default URL if no saved request
         }
	}
}
