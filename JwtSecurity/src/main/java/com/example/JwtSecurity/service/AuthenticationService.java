package com.example.JwtSecurity.service;

import java.util.HashMap;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.JwtSecurity.dto.JwtAuthenticationRequest;
import com.example.JwtSecurity.dto.JwtAuthenticationResponse;
import com.example.JwtSecurity.dto.RefreshTokenRequest;
import com.example.JwtSecurity.dto.SignUp;
import com.example.JwtSecurity.entities.User;
import com.example.JwtSecurity.entities.UserPrincipal;
import com.example.JwtSecurity.repository.UserRepository;

@Service
public class AuthenticationService {

	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	AuthenticationManager authenticationManager;
	
	@Autowired
	JwtTokenUtilService jwtTokenUtilService;
	
	public User saveUser(SignUp usr) {
		
		User user=new User();
		user.setName(usr.getName());
		user.setEmail(usr.getEmail());
		user.setPassword(passwordEncoder.encode(usr.getPassword()));
		user.setRole(usr.getRole());
		return userRepository.save(user);
	}
	
	public JwtAuthenticationResponse signin(JwtAuthenticationRequest signinreq) {
		
		String jwtToken=null;
		String refreshToken=null;
		JwtAuthenticationResponse jwtAuthenticationResponse=null; 
		
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(signinreq.getEmail(),signinreq.getPassword()));
			
		User user = userRepository.findByEmail(signinreq.getEmail());
		jwtToken = jwtTokenUtilService.generateToken(new UserPrincipal(user));
		refreshToken = jwtTokenUtilService.generateRefreshToken(new HashMap<>(), new UserPrincipal(user));

		jwtAuthenticationResponse = new JwtAuthenticationResponse();
		jwtAuthenticationResponse.setJwtToken(jwtToken);
		jwtAuthenticationResponse.setRefreshToken(refreshToken);
		return jwtAuthenticationResponse;
		
	}
	
	public JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {
		String jwtToken=null;
		
		String userEmail=jwtTokenUtilService.extractUsername(refreshTokenRequest.getToken());
		User user=userRepository.findByEmail(userEmail);
//		if(user!=null) {
			if(jwtTokenUtilService.isTokenValid(refreshTokenRequest.getToken(), new UserPrincipal(user))) {
				jwtToken=jwtTokenUtilService.generateToken(new UserPrincipal(user));
				JwtAuthenticationResponse jwtAuthenticationResponse=new JwtAuthenticationResponse();
				jwtAuthenticationResponse.setJwtToken(jwtToken);
				jwtAuthenticationResponse.setRefreshToken(refreshTokenRequest.getToken());
				return jwtAuthenticationResponse;
			}
			return null;
//		}
	}
}
