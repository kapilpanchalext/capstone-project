package com.java.auth.filter;

import java.io.IOException;

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
                    UsernamePasswordAuthenticationToken authRequest =
                            new UsernamePasswordAuthenticationToken("admin@email.com", "1234");
                    
                    Authentication authResult = authenticationManager.authenticate(authRequest);
                    SecurityContextHolder.getContext().setAuthentication(authResult);

                    // Set the authenticated session
                    HttpSession newSession = request.getSession(true);
                    newSession.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                            SecurityContextHolder.getContext());

                    // Log success
                    System.out.println("User authenticated successfully.");
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
