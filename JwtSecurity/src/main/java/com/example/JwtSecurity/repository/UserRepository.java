package com.example.JwtSecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.JwtSecurity.entities.User;

@Repository
public interface UserRepository extends JpaRepository<User,Integer>{

	User findByEmail(String email);

}
