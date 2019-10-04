package com.example.jwt.security.SecurityJWT;

import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;


@Service
public class SecurityJWT {

    //private Key key;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public SecurityJWT(){

        Path path = Paths.get("Private.key");
        try{
            byte[] bytes = Files.readAllBytes(path);

            /* Generate private key. */
            PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            privateKey = kf.generatePrivate(ks);
        }catch (Exception e){
            System.out.println(e.getMessage());
        }

        /*
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        privateKey = (PrivateKey) keyPair.getPrivate();
        publicKey = (PublicKey) keyPair.getPublic();
        try {
            FileOutputStream privateFileKey = new FileOutputStream("Private.key");
            privateFileKey.write(privateKey.getEncoded());
            privateFileKey.close();

            FileOutputStream publicFileKey = new FileOutputStream("Public.key");
            publicFileKey.write(publicKey.getEncoded());
            publicFileKey.close();
        }catch (Exception e){
            System.out.println(e.getMessage());
        }*/
        //key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    }

    public String getToken(Map<String,Object> mapClaims){
        return Jwts.builder().setClaims(mapClaims).signWith(privateKey, SignatureAlgorithm.RS256).compact();
    }

    public Map<String,Object> decrypt(String mapClaims){
        Path path = Paths.get("Public.key");
        try {
            byte[] bytes = Files.readAllBytes(path);
            X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            publicKey = kf.generatePublic(ks);
        }catch (Exception e){
            System.out.println(e.getMessage());
        }
        return Jwts.parser().setSigningKey(publicKey).parseClaimsJws(mapClaims).getBody();
    }
}
