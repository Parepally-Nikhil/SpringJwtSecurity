package com.example.JwtSecurity.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.JwtSecurity.entities.User;
import com.example.JwtSecurity.entities.UserPrincipal;
import com.example.JwtSecurity.repository.UserRepository;

@Service
public class JwtUserDetailsService implements UserDetailsService{

	@Autowired
	private UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user=userRepository.findByEmail(username);
		if(user!=null) {
			return new UserPrincipal(user);
		}
		throw new UsernameNotFoundException("User not found with username: " + username);
	}
	
	
}
