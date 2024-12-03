package com.java.oauth.model;

import java.io.Serializable;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "roles")
@Getter @Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Role implements Serializable {
	private static final long serialVersionUID = 4066870267891532305L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "role_id", nullable = false, unique = true)
	private long role_id;
	
	@Column(unique = true, nullable = false)
	private String name;
	
	@ManyToMany(mappedBy = "roles", fetch = FetchType.LAZY)
	@JsonIgnore
    private Set<Student> student;

	@Override
	public String toString() {
		return "Role [role_id=" + role_id + ", name=" + name + "]";
	}
}
