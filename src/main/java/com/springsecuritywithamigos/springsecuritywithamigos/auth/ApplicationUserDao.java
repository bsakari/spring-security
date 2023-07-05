package com.springsecuritywithamigos.springsecuritywithamigos.auth;

import org.springframework.stereotype.Component;

import java.util.Optional;

public interface ApplicationUserDao {
    Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
