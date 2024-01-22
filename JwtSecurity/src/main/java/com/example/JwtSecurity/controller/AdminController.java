package com.example.JwtSecurity.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class AdminController {

	@GetMapping("/admin")
	public ResponseEntity<String> getAdmin() {
		return ResponseEntity.ok("Admin Controller");
	}
	
}
