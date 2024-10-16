package com.saadmeddiche.creditmanagement.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ROLES {
    USER("user"),
    ADMIN("admin");

    private final String value;
}
