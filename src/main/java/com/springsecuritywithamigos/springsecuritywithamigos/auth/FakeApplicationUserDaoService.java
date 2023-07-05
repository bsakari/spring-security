package com.springsecuritywithamigos.springsecuritywithamigos.auth;

import com.google.common.collect.Lists;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

import static com.springsecuritywithamigos.springsecuritywithamigos.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao{
    private final PasswordEncoder passwordEncoder;

    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers(){
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(STUDENT.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "kingwanyama",
                        true,
                        true,

                        true,
                        true),
                new ApplicationUser(ADMIN.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "wanyamaking",
                        true,
                        true,

                        true,
                        true),
                new ApplicationUser(ADMINTRAINEE.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "ajani",
                        true,
                        true,

                        true,
                        true)
        );
        return applicationUsers;
    }
}
