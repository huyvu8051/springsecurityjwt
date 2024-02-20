package com.huyvu.springsecurityjwt.controller;

import com.huyvu.springsecurityjwt.security.JwtTokenVo;
import com.huyvu.springsecurityjwt.security.SecurityUtils;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;

@RestController
public class HomeController {

    @GetMapping
    String signing(Long uId, String username, String[] roles, HttpServletResponse res){
        var token = SecurityUtils.createToken(new JwtTokenVo(uId, username, Arrays.stream(roles).toList()));
        SecurityUtils.setToken(res, token);
        return "signed";
    }


    @GetMapping("/secured")
    String secured(){
        var session = SecurityUtils.getSession();
        return "Secured " + session;
    }

    @GetMapping("/admin")
    String admin(){
        var session = SecurityUtils.getSession();
        return "Admin " + session;
    }


    @PreAuthorize("hasAuthority('guest')")
    @GetMapping("/guest")
    String guest(){
        var session = SecurityUtils.getSession();
        return "Guest " + session;
    }


    @GetMapping("/business")
    String business(){
        var session = SecurityUtils.getSession();
        return "Business " + session;
    }
}
