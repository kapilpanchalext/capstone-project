package com.java.registration.model;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "student")
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Student implements Serializable {
	private static final long serialVersionUID = 7366456153337391645L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;

	@Column(name = "student_id")
	private int student_id;
	
	private String name;
	
	@Column(unique = true, nullable = false)
	private String email;

	@Column(name = "mobile_number", nullable = false)
	private String mobileNumber;

	@JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
	private String password;

	@Column(name = "created_date", unique = true, nullable = false, updatable = false)
	@JsonIgnore
	@Builder.Default
	private LocalDateTime createdDate = LocalDateTime.now();

	@Column(name = "created_by", updatable = false)
	@JsonIgnore
	@Builder.Default
	private String createdBy = "admin";

	@Column(name = "last_modified_date", unique = true, nullable = false)
	@JsonIgnore
	@Builder.Default
	private LocalDateTime lastModifiDate = LocalDateTime.now();

	@Column(name = "last_modified_by")
	@JsonIgnore
	@Builder.Default
	private String lastModifiedBy = "admin";

    @ManyToMany(cascade = CascadeType.PERSIST, fetch = FetchType.EAGER)
    @JoinTable(
        name = "student_roles",
        joinColumns = @JoinColumn(name = "student_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles;
}
