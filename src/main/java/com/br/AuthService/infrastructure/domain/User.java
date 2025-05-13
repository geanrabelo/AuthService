package com.br.AuthService.infrastructure.domain;

import com.br.AuthService.infrastructure.enums.Roles;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Entity
@Table(name = "tb_user")
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@EqualsAndHashCode(of = "id")
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String login;
    private String password;

    @Enumerated(EnumType.STRING)
    private Roles roles;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    private boolean enabled;

    public User(String login, String password, Roles roles){
        this.login = login;
        this.password = password;
        this.roles = roles;
        this.createdAt = LocalDateTime.now();
        this.enabled = true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if(this.roles == Roles.ADMIN) return List.of(new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("ROLE_TECHNICIAN"), new SimpleGrantedAuthority("ROLE_AUDITOR"));
        else if (this.roles == Roles.TECHNICIAN) {
            return List.of(new SimpleGrantedAuthority("ROLE_TECHNICIAN"), new SimpleGrantedAuthority("ROLE_AUDITOR"));
        }else {
            return List.of(new SimpleGrantedAuthority("ROLE_AUDITOR"));
        }
    }

    @Override
    public String getUsername(){
        return this.login;
    }

    @Override
    public String getPassword(){
        return this.password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
}
