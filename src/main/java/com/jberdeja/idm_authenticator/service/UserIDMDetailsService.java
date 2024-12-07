package com.jberdeja.idm_authenticator.service;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import com.jberdeja.idm_authenticator.repository.UserIDMRepository;
import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class UserIDMDetailsService implements UserDetailsService{
    private final UserIDMRepository userIDMRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userIDMRepository.findByEmail(username)
            .map(
                user->{ 
                    final var authorities = user.getRoles()
                    .stream()
                    .map(
                        role->new SimpleGrantedAuthority(role.getRoleName())
                    ).toList();

                return new User(user.getEmail(), user.getPwd(), authorities);

        }).orElseThrow(()->new UsernameNotFoundException("User not exist " + username));
    }


}
