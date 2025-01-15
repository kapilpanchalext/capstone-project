package com.java.auth.api;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginPageController {

//	@GetMapping("/custom-login")
//    public String customLogin() {
//        return "<!DOCTYPE html>\r\n"
//        		+ "<html lang=\"en\">\r\n"
//        		+ "<head>\r\n"
//        		+ "    <meta charset=\"UTF-8\">\r\n"
//        		+ "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\r\n"
//        		+ "    <title>Custom Login</title>\r\n"
//        		+ "    <style>\r\n"
//        		+ "        body {\r\n"
//        		+ "            font-family: Arial, sans-serif;\r\n"
//        		+ "            background-color: #f4f4f4;\r\n"
//        		+ "            margin: 0;\r\n"
//        		+ "            padding: 0;\r\n"
//        		+ "            display: flex;\r\n"
//        		+ "            justify-content: center;\r\n"
//        		+ "            align-items: center;\r\n"
//        		+ "            height: 100vh;\r\n"
//        		+ "        }\r\n"
//        		+ "        .login-container {\r\n"
//        		+ "            background: #fff;\r\n"
//        		+ "            padding: 20px;\r\n"
//        		+ "            border-radius: 5px;\r\n"
//        		+ "            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);\r\n"
//        		+ "            width: 300px;\r\n"
//        		+ "        }\r\n"
//        		+ "        .login-container h1 {\r\n"
//        		+ "            text-align: center;\r\n"
//        		+ "            margin-bottom: 20px;\r\n"
//        		+ "        }\r\n"
//        		+ "        .login-container input {\r\n"
//        		+ "            width: 100%;\r\n"
//        		+ "            padding: 10px;\r\n"
//        		+ "            margin: 10px 0;\r\n"
//        		+ "            border: 1px solid #ccc;\r\n"
//        		+ "            border-radius: 4px;\r\n"
//        		+ "        }\r\n"
//        		+ "        .login-container button {\r\n"
//        		+ "            width: 100%;\r\n"
//        		+ "            padding: 10px;\r\n"
//        		+ "            background-color: #007BFF;\r\n"
//        		+ "            color: white;\r\n"
//        		+ "            border: none;\r\n"
//        		+ "            border-radius: 4px;\r\n"
//        		+ "            cursor: pointer;\r\n"
//        		+ "        }\r\n"
//        		+ "        .login-container button:hover {\r\n"
//        		+ "            background-color: #0056b3;\r\n"
//        		+ "        }\r\n"
//        		+ "    </style>\r\n"
//        		+ "</head>\r\n"
//        		+ "<body>\r\n"
//        		+ "    <div class=\"login-container\">\r\n"
//        		+ "        <h1>Login</h1>\r\n"
//        		+ "        <form method=\"post\" action=\"/login\">\r\n"
//        		+ "            <input type=\"text\" name=\"username\" placeholder=\"Username\" required>\r\n"
//        		+ "            <input type=\"password\" name=\"password\" placeholder=\"Password\" required>\r\n"
//        		+ "            <button type=\"submit\">Login</button>\r\n"
//        		+ "        </form>\r\n"
//        		+ "    </div>\r\n"
//        		+ "</body>\r\n"
//        		+ "</html>";
//    }
	
	@GetMapping("/custom-login")
    public ResponseEntity<String> customLogin() {
		try {
            Path filePath = new ClassPathResource("static/index.html").getFile().toPath();
            String htmlContent = Files.readString(filePath);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.TEXT_HTML);

            return ResponseEntity.status(HttpStatus.OK).headers(headers).body(htmlContent);
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }
}
