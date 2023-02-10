package com.groupten.datawiz.service;

import com.groupten.datawiz.model.SecurityUser;
import com.groupten.datawiz.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class SecurityUserDetailsService implements UserDetailsService  {

    @Autowired
    UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        SecurityUser user = userRepository.findByUsername(username).map(SecurityUser::new)
                .orElseThrow(() -> new UsernameNotFoundException("User not present"));
        return user;
    }
}
