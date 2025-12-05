package com.zosh.Services;


import com.zosh.model.USER_ROLE;
import com.zosh.model.User;
import com.zosh.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

//    @Autowired
//    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
     User user=userRepository.findByEmail(username);

     if(user  !=null){
         throw new UsernameNotFoundException("User not found Exception "+username);
     }

     USER_ROLE role=user.getRole();
     if(role == null) ;

     List<GrantedAuthority> authorities=new ArrayList<>();

     authorities.add(new SimpleGrantedAuthority(role.toString()));

     return  new org.springframework.security.core.userdetails.User(user.getEmail(),user.getPassword(),authorities);

    }
}
