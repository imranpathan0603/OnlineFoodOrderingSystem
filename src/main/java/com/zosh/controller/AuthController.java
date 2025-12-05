package com.zosh.controller;


import com.zosh.Request.LoginRequest;
import com.zosh.Response.AuthResponse;
import com.zosh.Services.CustomUserDetailsService;
import com.zosh.config.JwtProvider;
import com.zosh.model.Cart;
import com.zosh.model.User;
import com.zosh.repo.CartRepository;
import com.zosh.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtProvider jwtProvider;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private CartRepository cartRepository;

    @PostMapping("/signup")

    public ResponseEntity<AuthResponse>createUserHandler(@RequestBody User user) throws Exception{
        User isEmailExist=userRepository.findByEmail(user.getEmail());
        if(isEmailExist!=null){
            throw new Exception("Email is already used with another account");
        }


        User createdUser=new User();
        createdUser.setEmail(user.getEmail());
        createdUser.setFullName(user.getFullName());
        createdUser.setRole(user.getRole());
        createdUser.setPassword(passwordEncoder.encode(user.getPassword()));

        User savedUser=userRepository.save(createdUser);

        Cart cart=new Cart();
        cart.setCustomer(savedUser);
        cartRepository.save(cart);

        Authentication authentication=new UsernamePasswordAuthenticationToken(user.getEmail(),user.getPassword());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt=jwtProvider.generateToken(authentication);

        AuthResponse authResponse=new AuthResponse();
//        authResponse.setJwt(jwt);
        authResponse.setMessage("Register Success");
        authResponse.setRole(savedUser.getRole());

        return new ResponseEntity<>(authResponse, HttpStatus.CREATED);
    }


public  ResponseEntity<AuthResponse> signin(@RequestBody LoginRequest req){



        String username= req.getEmail();
        String password=req.getPassword();

        Authentication authentication=authenticate(username,password);


        String jwt=jwtProvider.generateToken(authentication);
    AuthResponse authResponse=new AuthResponse();
    authResponse.setJwt(jwt);
    authResponse.setMessage("Login Success");
//    authResponse.setRole(savedUser.getRole());

    return new ResponseEntity<>(authResponse, HttpStatus.OK);
}

    private Authentication authenticate(String username, String password) {

        UserDetails userDetails=customUserDetailsService.loadUserByUsername(username);
        if(userDetails==null){

            throw  new BadCredentialsException("Invalid Username..");

        }

        if(!passwordEncoder.matches(password,userDetails.getPassword())){
            throw  new BadCredentialsException("invalid password.....");
        }
        return new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());

    }

}