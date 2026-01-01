package com.vehiclestore.domain;

import jakarta.persistence.*;

// User Entity - Maps to 'users' table in database
// JPA Entity represents a table in the database
// Each instance of User = one row in 'users' table
@Entity
@Table(name = "users")
public class User {

    // Primary key with auto-increment
    // @Id = marks this field as primary key
    // @GeneratedValue(IDENTITY) = auto-increment in MySQL
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private String email; // Used as username for authentication
    private String password; // Stored as BCrypt hash, NOT plain text;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

}
