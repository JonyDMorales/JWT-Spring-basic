package com.example.jwt.security.controller;

import com.example.jwt.security.SecurityJWT.SecurityJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class SecurityController {

    @Autowired
    public SecurityJWT securityJWT;

    @PostMapping("/security")
    public Map<String, String> secure(){
        Map<String, String> res = new HashMap<>();
        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "Jonatan");
        claims.put("email", "jony@stratosmex.com");
        claims.put("password","1234");
        res.put("token", securityJWT.getToken(claims));
        return res;
    }

    @PostMapping("/decrypt")
    public Map<String, Object> decrypt(@RequestParam("token") String cifrado){
        return securityJWT.decrypt(cifrado);
    }

}
