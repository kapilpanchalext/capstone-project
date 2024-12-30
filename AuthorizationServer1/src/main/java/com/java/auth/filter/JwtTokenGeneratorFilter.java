package com.java.auth.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtTokenGeneratorFilter extends OncePerRequestFilter{

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		
		if(authentication != null) {
			Environment env = getEnvironment();
			
			if(env != null) {
				String secret = env.getProperty("JWT_SECRET", 
						"$2a$12$JbnxIJbhzcPMK3452345324234xXCOL49BekIcqu41ZAMfDL0pQ/J58zhX5WhgZlIC");
				SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
				String jwt = Jwts
					.builder()
					.issuer("application1")
					.subject("JWTToken")
					.claim("username", authentication.getName())
					.claim("authorities", authentication
											.getAuthorities()
											.stream()
											.map(GrantedAuthority::getAuthority)
											.collect(Collectors.joining(",")))
					.issuedAt(new Date())
					.expiration(new Date(new Date().getTime() + 30000000))
					.signWith(secretKey).compact();
				response.setHeader("Authorization", jwt);
			}
		}
		filterChain.doFilter(request, response);
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
		return !request.getServletPath().equals("/api/v1/helloworld");
	}
}
