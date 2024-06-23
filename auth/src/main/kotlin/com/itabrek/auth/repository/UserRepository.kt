package com.itabrek.auth.repository

import com.itabrek.auth.entity.User
import org.springframework.data.r2dbc.repository.R2dbcRepository
import reactor.core.publisher.Mono

interface UserRepository : R2dbcRepository<User, Long> {
    fun findByUsername(username: String): Mono<User?>
}