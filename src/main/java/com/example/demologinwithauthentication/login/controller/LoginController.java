package com.example.demologinwithauthentication.login.controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @RequestMapping({ "/hello" })
    public String hello() {
        return "Hello World";
    }

}
