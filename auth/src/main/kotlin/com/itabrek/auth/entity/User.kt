package com.itabrek.auth.entity

import org.springframework.data.annotation.Id
import org.springframework.data.relational.core.mapping.Table

@Table("users")
class User(
    @Id
    var id: Long? = null,
    var username: String,
    var password: String
)