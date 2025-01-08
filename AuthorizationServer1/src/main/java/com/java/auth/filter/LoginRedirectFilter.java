package com.java.auth.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class LoginRedirectFilter implements Filter {

    private final AuthenticationManager authenticationManager;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            HttpServletResponse httpResponse = (HttpServletResponse) response;

//            if (httpRequest.getRequestURI().equals("/login") && "POST".equalsIgnoreCase(httpRequest.getMethod())) {
                String authHeader = httpRequest.getHeader("Authorization");

                if (authHeader != null && authHeader.startsWith("Basic ")) {
                    String[] credentials = decodeBasicAuth(authHeader);
                    String username = credentials[0];
                    String password = credentials[1];

                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(username, password);

                    try {
                        Authentication authentication = authenticationManager.authenticate(authToken);
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    } catch (AuthenticationException ex) {
                        httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication Failed");
                        return;
                    }
                }
//            }
        }
        chain.doFilter(request, response);
	}

	private String[] decodeBasicAuth(String authHeader) {
		String base64Credentials = authHeader.substring("Basic ".length());
        String credentials = new String(Base64.getDecoder().decode(base64Credentials), StandardCharsets.UTF_8);
        return credentials.split(":", 2);
	}
}
