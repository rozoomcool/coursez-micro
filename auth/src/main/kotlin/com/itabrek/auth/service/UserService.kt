package com.itabrek.auth.service

import com.itabrek.auth.entity.User
import com.itabrek.auth.repository.UserRepository
import kotlinx.coroutines.reactor.awaitSingle
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono


@Service
class UserService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder
) : ReactiveUserDetailsService {

    override fun findByUsername(username: String): Mono<UserDetails> {
        return userRepository.findByUsername(username)
            .switchIfEmpty(Mono.error(UsernameNotFoundException("User not found")))
            .map { user ->
                org.springframework.security.core.userdetails.User.withUsername(user!!.username).password(
                    user.password
                ).roles("USER").build()
            }
    }

    fun saveUser(user: User): Mono<User> {
        user.password = passwordEncoder.encode(user.password)
        return userRepository.save(user)
    }
}