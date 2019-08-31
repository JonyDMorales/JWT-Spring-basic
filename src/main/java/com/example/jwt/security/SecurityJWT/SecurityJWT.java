package com.example.jwt.security.SecurityJWT;

import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;


@Service
public class SecurityJWT {

    //private Key key;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public SecurityJWT(){
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        privateKey = (PrivateKey) keyPair.getPrivate();
        publicKey = (PublicKey) keyPair.getPublic();
        //key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    }

    public String getToken(Map<String,Object> mapClaims){
        return Jwts.builder().setClaims(mapClaims).signWith(privateKey, SignatureAlgorithm.RS256).compact();
    }

    public Map<String,Object> decrypt(String mapClaims){
        return Jwts.parser().setSigningKey(publicKey).parseClaimsJws(mapClaims).getBody();
    }
}
