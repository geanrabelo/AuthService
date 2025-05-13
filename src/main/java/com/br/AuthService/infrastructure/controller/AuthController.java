package com.br.AuthService.infrastructure.controller;

import com.br.AuthService.infrastructure.domain.User;
import com.br.AuthService.infrastructure.dto.AuthenticationDTO;
import com.br.AuthService.infrastructure.dto.MessageDTO;
import com.br.AuthService.infrastructure.dto.RegisterDTO;
import com.br.AuthService.infrastructure.dto.TokenDTO;
import com.br.AuthService.infrastructure.repositories.UserRepository;
import com.br.AuthService.infrastructure.service.TokenService;
import com.br.AuthService.infrastructure.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final TokenService tokenService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final KafkaTemplate<String, String> kafkaTemplate;

    public AuthController(TokenService tokenService,
                          AuthenticationManager authenticationManager,
                          UserRepository userRepository,
                          KafkaTemplate<String, String> kafkaTemplate){
        this.tokenService = tokenService;
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.kafkaTemplate = kafkaTemplate;
    }

    @PostMapping("/login")
    @Transactional
    public ResponseEntity<TokenDTO> login(@RequestBody @Validated AuthenticationDTO authenticationDTO){
        var usernamePassword = new UsernamePasswordAuthenticationToken(authenticationDTO.login(), authenticationDTO.password());
        var authentication = authenticationManager.authenticate(usernamePassword);

        String token = tokenService.generateToken((User) authentication.getPrincipal());

        //kafkaTemplate.send("auth", token);
        return ResponseEntity.ok(new TokenDTO(token));
    }

    @PostMapping("/register")
    @Transactional
    public ResponseEntity<?> register(@RequestBody @Validated RegisterDTO registerDTO){
        if(userRepository.findByLogin(registerDTO.login()) != null) return ResponseEntity.badRequest().body("Already exists user with username");
        var passwordCrypt = new BCryptPasswordEncoder().encode(registerDTO.password());
        User user = new User(registerDTO.login(), passwordCrypt, registerDTO.roles());

        userRepository.save(user);
        return ResponseEntity.ok(new MessageDTO("User registered successfully"));
    }
}
