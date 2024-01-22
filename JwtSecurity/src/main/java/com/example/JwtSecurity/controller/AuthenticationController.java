package com.example.JwtSecurity.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.JwtSecurity.dto.JwtAuthenticationRequest;
import com.example.JwtSecurity.dto.JwtAuthenticationResponse;
import com.example.JwtSecurity.dto.RefreshTokenRequest;
import com.example.JwtSecurity.dto.SignUp;
import com.example.JwtSecurity.entities.User;
import com.example.JwtSecurity.service.AuthenticationService;

@RestController
@RequestMapping("/api")
public class AuthenticationController {
	
	@Autowired
	AuthenticationService authenticationService;
	
	@PostMapping("/signup")
	public ResponseEntity<User> signUp(@RequestBody SignUp usr) {
		
		User user=authenticationService.saveUser(usr);
		return new ResponseEntity<User>(user,HttpStatus.OK);
	}
	
	@PostMapping("/signin")
	public ResponseEntity<JwtAuthenticationResponse> signIn(@RequestBody JwtAuthenticationRequest jreq){
		return ResponseEntity.ok(authenticationService.signin(jreq));
	}
	
	@PostMapping("/refreshtoken")
	public ResponseEntity<JwtAuthenticationResponse> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest){
		return ResponseEntity.ok(authenticationService.refreshToken(refreshTokenRequest));
	}

}
