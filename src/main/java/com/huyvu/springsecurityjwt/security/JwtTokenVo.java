package com.huyvu.springsecurityjwt.security;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.core.GrantedAuthority;

import java.util.ArrayList;
import java.util.List;

import static lombok.AccessLevel.PRIVATE;


@Data
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = PRIVATE)
public class JwtTokenVo {
    Long uId;
    String username;
    List<String> roles;

    List<GrantedAuthority> getAuthorities() {
        if (roles == null) return new ArrayList<>();
        return roles.stream().map(s -> (GrantedAuthority) () -> s).toList();
    }

}