package com.java.auth.config;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.java.auth.model.Student;
import com.java.auth.repository.StudentRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class StudentUserDetailsService implements UserDetailsService {
	
	private final StudentRepository repo;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Student student = repo.findByEmail(username).orElseThrow(() -> new
	                UsernameNotFoundException("User details not found for the user: " + username));
        
		List<GrantedAuthority> authorities = student
					.getRoles()
					.stream()
					.map(role -> new
	                SimpleGrantedAuthority(role.getName())).collect(Collectors.toList());
        
	    return new User(student.getEmail(), student.getPassword(), authorities);
	}
}
