package com.vehiclestore.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.vehiclestore.domain.User;

// Repository layer - Direct communication with database
// Extends JpaRepository<Entity, PrimaryKeyType> to get CRUD methods for free:
// - save(), findById(), findAll(), deleteById(), etc.
// Spring Data JPA auto-generates implementation at runtime
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // Custom query method - Spring generates SQL automatically based on method name
    // findByEmail -> SELECT * FROM users WHERE email = ?
    // Used by UserDetailCustom to find user during authentication
    User findByEmail(String email);
}
