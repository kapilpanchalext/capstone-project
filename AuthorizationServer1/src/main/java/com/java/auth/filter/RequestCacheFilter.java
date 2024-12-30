package com.java.auth.filter;

import java.io.IOException;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class RequestCacheFilter extends OncePerRequestFilter {

	private final RequestCache requestCache = new HttpSessionRequestCache();
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		if (!SecurityContextHolder.getContext().getAuthentication().isAuthenticated()) {
	            requestCache.saveRequest(request, response);
		}
		System.err.println(requestCache.toString());
        filterChain.doFilter(request, response);
	}
}
