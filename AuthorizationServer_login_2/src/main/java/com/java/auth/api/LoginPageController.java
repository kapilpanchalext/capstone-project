package com.java.auth.api;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginPageController {

	@GetMapping("/custom-login")
    public String customLogin() {
        return "login.html";
    }
}
