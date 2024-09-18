package com.webwarder.security.controller;


import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

@RestController
@RequestMapping("/api")
public class SecurityController {

    @GetMapping("/auth")
    public HashMap index() {
        OAuth2User user = ((OAuth2User) SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        return new HashMap() {{
            put("Hello" , user.getAttribute("name"));
            put("Email" , user.getAttribute("email"));
        }};
    }

    @GetMapping("/unauth")
    public HashMap unauthenticatedRequest() {
        return new HashMap() {{
            put("this is" , "unautheticated");
        }};
    }

}
