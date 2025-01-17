package com.java.auth.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@Component
public class CustomAuthorizationFilter extends OncePerRequestFilter {
	
	@Autowired
    private AuthenticationManager authenticationManager;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		String path = request.getRequestURI();

        // Intercept the OAuth2 authorize request
        if (path.equals("/oauth2/authorize")) {
            HttpSession session = request.getSession(false);

            if (session == null || SecurityContextHolder.getContext().getAuthentication() == null) {
                try {
//                     Authenticate the user programmatically
                	String authHeader = request.getHeader("Authorization");
                	if (true) {
                	
                	if (authHeader != null && authHeader.startsWith("Basic ")) {
                        // Decode Base64 credentials
                        String base64Credentials = authHeader.substring("Basic ".length());
                        String credentials = new String(Base64.getDecoder().decode(base64Credentials), StandardCharsets.UTF_8);

                        // Split into username and password
                        String[] values = credentials.split(":", 2);
                        if (values.length == 2) {
                            String username = values[0];
                            String password = values[1];
                	
                    UsernamePasswordAuthenticationToken authRequest =
                            new UsernamePasswordAuthenticationToken(username, password);
                	
//                    UsernamePasswordAuthenticationToken authRequest =
//                            new UsernamePasswordAuthenticationToken("admin@email.com", "1234");
                    
                    Authentication authResult = authenticationManager.authenticate(authRequest);
                    SecurityContextHolder.getContext().setAuthentication(authResult);

                    // Set the authenticated session
                    HttpSession newSession = request.getSession(true);
                    newSession.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                            SecurityContextHolder.getContext());

                    // Log success
                    System.out.println("User authenticated successfully.");
                        }
                        }
                    }
                } catch (AuthenticationException e) {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication Failed");
                    return;
                }
            }
        }

        // Proceed with the filter chain
        filterChain.doFilter(request, response);
	}
}
