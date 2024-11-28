package com.java.registration.config;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.java.registration.model.Student;
import com.java.registration.repository.StudentRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class StudentUserDetailsService implements UserDetailsService{

	private final StudentRepository repo;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Student student = repo.findByEmail(username).orElseThrow(() -> 
		new UsernameNotFoundException("User details not found for username: " + username));
		
		List<GrantedAuthority> authorities = student
				.getRoles()
				.stream()
				.map(authority -> new
                SimpleGrantedAuthority(authority.getName()))
				.collect(Collectors.toList());
		
		System.err.println("SIMPLE GRANTED AUTHORITIES: " + authorities);
		return new User(student.getEmail(), student.getPassword(), authorities);
	}
}
