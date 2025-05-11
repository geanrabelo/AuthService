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

@Entity(name = "tb_user")
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

    private String username;
    private String password;

    private Roles roles;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    private boolean enabled;

    public User(String username, String password, Roles roles){
        this.username = username;
        this.password = password;
        this.roles = roles;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if(this.roles == Roles.ADMIN) return List.of(new SimpleGrantedAuthority("ADMIN"), new SimpleGrantedAuthority("TECHNICIAN"), new SimpleGrantedAuthority("AUDITOR"));
        else if (this.roles == Roles.TECHNICIAN) {
            return List.of(new SimpleGrantedAuthority("TECHNICIAN"), new SimpleGrantedAuthority("AUDITOR"));
        }else {
            return List.of(new SimpleGrantedAuthority("AUDITOR"));
        }
    }

    @Override
    public String getUsername(){
        return this.username;
    }

    @Override
    public String getPassword(){
        return this.password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }
}
