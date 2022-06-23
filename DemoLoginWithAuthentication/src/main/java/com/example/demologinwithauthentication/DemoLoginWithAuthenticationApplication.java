package com.example.demologinwithauthentication;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication(exclude = {SecurityAutoConfiguration.class })
//@SpringBootApplication
public class DemoLoginWithAuthenticationApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoLoginWithAuthenticationApplication.class, args);
    }

}
