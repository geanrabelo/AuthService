package com.br.AuthService.infrastructure.dto;

import com.br.AuthService.infrastructure.enums.Roles;

public record RegisterDTO(String login,
                          String password,
                          Roles roles) {
}
