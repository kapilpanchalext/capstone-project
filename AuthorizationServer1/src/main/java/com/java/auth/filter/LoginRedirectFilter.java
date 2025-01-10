package com.java.auth.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Map;

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
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class LoginRedirectFilter implements Filter {
	
	private static final String SPRING_SECURITY_FORM_USERNAME_KEY = "username";
    private static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "password";

    private final AuthenticationManager authenticationManager;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            
            Enumeration<String> attribNames = request.getAttributeNames();
            // Iterate through attribute names
            while (attribNames.hasMoreElements()) {
                String attribName = attribNames.nextElement();
                Object attribValue = request.getAttribute(attribName);

                // Print or process the attribute name and value
                System.err.println("Attribute Name: " + attribName);
                System.err.println("Attribute Value: " + attribValue);
            }
            
            Enumeration<String> parameterNames = request.getParameterNames();
            // Iterate through attribute names
            while (parameterNames.hasMoreElements()) {
                String paramName = parameterNames.nextElement();
                Object paramValue = request.getAttribute(paramName);

                // Print or process the attribute name and value
                System.err.println("Param Name: " + paramName);
                System.err.println("Param Value: " + paramValue);
            }
            
            Enumeration<String> headerNames = httpRequest.getHeaderNames();
            // Iterate through attribute names
            while (headerNames.hasMoreElements()) {
                String headerName = headerNames.nextElement();
                Object headerValue = httpRequest.getHeaders(headerName);
                // Print or process the attribute name and value
                System.err.println("Header Name: " + headerName);
                System.err.println("Header Value: " + headerValue);
            }
            
            Map<String,String[]> parameterMap = request.getParameterMap();
            for(Map.Entry<String, String[]> entry : parameterMap.entrySet()) {
            	System.err.println("Key: " + entry.getKey() + " : Value: " + Arrays.toString(entry.getValue()));
            }
            
            System.err.println(parameterMap);
            
//            if (httpRequest.getRequestURI().equals("/login") && "POST".equalsIgnoreCase(httpRequest.getMethod())) {
                String authHeader = httpRequest.getHeader("Authorization");

                if (authHeader != null && authHeader.startsWith("Basic ")) {
                    String[] credentials = decodeBasicAuth(authHeader);
                    String username = credentials[0];
                    String password = credentials[1];

                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(username, password);

                    try {
                        // Wrap the request to add username and password parameters
//                        HttpServletRequest wrappedRequest = new HttpServletRequestWrapper(httpRequest) {
//                            @Override
//                            public String getParameter(String name) {
//                                if (SPRING_SECURITY_FORM_USERNAME_KEY.equals(name)) {
//                                    return username;
//                                } else if (SPRING_SECURITY_FORM_PASSWORD_KEY.equals(name)) {
//                                    return password;
//                                }
//                                return super.getParameter(name);
//                            }
//                        };
//                        Authentication authentication = authenticationManager.authenticate(authToken);
//                        SecurityContextHolder.getContext().setAuthentication(authentication);
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
