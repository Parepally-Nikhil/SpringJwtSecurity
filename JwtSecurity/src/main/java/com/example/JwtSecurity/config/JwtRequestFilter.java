package com.example.JwtSecurity.config;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.JwtSecurity.service.JwtTokenUtilService;
import com.example.JwtSecurity.service.JwtUserDetailsService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

//In this class we will validate the jwt or token for every api or request.

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

	@Autowired
	private JwtUserDetailsService jwtUserDetailsService;
	
	@Autowired
	private JwtTokenUtilService jwtTokenUtilService;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		//this authHeader contains like "Bearer jwtToken.."
		final String authHeader=request.getHeader("Authorization");
		String jwtToken=null;
		String userEmail=null;
		
		if(authHeader!=null && authHeader.startsWith("Bearer ")) {
			jwtToken=authHeader.substring(7);
			userEmail=jwtTokenUtilService.extractUsername(jwtToken);
		}
		else {
            System.out.println("JWT Token does not begin with Bearer String");
        }
		
		// Once we get the token validate it.
		if(userEmail!=null && SecurityContextHolder.getContext().getAuthentication()==null) {
			UserDetails userDetails=jwtUserDetailsService.loadUserByUsername(userEmail);
	
			// if token is valid configure Spring Security to manually set
            // authentication
			if(jwtTokenUtilService.isTokenValid(jwtToken, userDetails)) {
				SecurityContext securityContext=SecurityContextHolder.createEmptyContext();
				
				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken=new UsernamePasswordAuthenticationToken(
					userDetails,null,userDetails.getAuthorities()
				);
				
				usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			
				// After setting the Authentication in the context, we specify
                // that the current user is authenticated. So it passes the
                // Spring Security Configurations successfully.
				securityContext.setAuthentication(usernamePasswordAuthenticationToken);
				SecurityContextHolder.setContext(securityContext);
				
				//below one is in a simple way
				//SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
			}
		}
		
		filterChain.doFilter(request, response);
	}
	

}
