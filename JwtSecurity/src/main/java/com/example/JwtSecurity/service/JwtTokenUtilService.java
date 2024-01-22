package com.example.JwtSecurity.service;

import java.util.Date;

import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

//This class is for generating the token and extracting the info like userName from our token.
//Or can take some fields of the token

@Service
public class JwtTokenUtilService {
	@Value("${jwt.secret}")
    private String secretKey;
	
    //while creating the token -
    //1. Define  claims of the token, like Issuer, Expiration, Subject, and the ID
    //2. Sign the JWT using the HS512 algorithm and secret key.
    //3. According to JWS Compact Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
    //   compaction of the JWT to a URL-safe string 
    
	public String generateToken(UserDetails userDetails) {
		return Jwts.builder().subject(userDetails.getUsername())
				.issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis()+1000*60*24))//1day
				.signWith(getSignKey())
				.compact();
	}
	
	public String generateRefreshToken(Map<String,Object> extraClaims,UserDetails userDetails) {
		return Jwts.builder().claims(extraClaims).subject(userDetails.getUsername())
				.issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis()+604800000))//7days
				.signWith(getSignKey())
				.compact();
	}
	
	public String extractUsername(String token) {
		//return extractClaim(token,(e)->{return e.getSubject(); });
		return extractClaim(token,Claims::getSubject);
	}
	
	private <T> T extractClaim(String token,Function<Claims,T> claimsResolvers) {
		final Claims claims=extractAllClaims(token);
		return claimsResolvers.apply(claims);
	}
	
	private Claims extractAllClaims(String token) {
		return Jwts.parser().verifyWith(getSignKey()).build().parseSignedClaims(token).getPayload();
	}
	
	public boolean isTokenValid(String token,UserDetails userDetails) {
		final String username=extractUsername(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}
	
	private boolean isTokenExpired(String token) {
		return extractClaim(token,Claims::getExpiration).before(new Date());
	}
	
	private SecretKey getSignKey() {
		SecretKey key=Keys.hmacShaKeyFor(secretKey.getBytes());
		return key;
	}
}
