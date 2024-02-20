package com.huyvu.springsecurityjwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;

@SpringBootApplication(exclude = {UserDetailsServiceAutoConfiguration.class})
public class SpringsecurityjwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringsecurityjwtApplication.class, args);
    }

}
