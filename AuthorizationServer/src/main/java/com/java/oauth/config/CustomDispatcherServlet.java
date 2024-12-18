package com.java.oauth.config;

import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.HandlerExecutionChain;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class CustomDispatcherServlet extends DispatcherServlet {

	@SuppressWarnings("deprecation")
    @Override
    protected void doDispatch(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpServletRequest processedRequest = request;
        HandlerExecutionChain mappedHandler = null;
        boolean multipartRequestParsed = false;

        // Custom logic before dispatching
        System.out.println("Custom doDispatch logic invoked");

        try {
            super.doDispatch(processedRequest, response);
        } finally {
            // Custom logic after dispatching
            System.out.println("Exiting doDispatch");
        }
    }
}
