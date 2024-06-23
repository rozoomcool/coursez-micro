package com.itabrek.auth.controller

import com.itabrek.auth.entity.User
import com.itabrek.auth.service.UserService
import com.itabrek.auth.util.JwtUtil
import org.springframework.http.ResponseEntity
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import reactor.core.publisher.Mono


@RestController
@RequestMapping("/auth")
class AuthController(
    private val userService: UserService,
    private val jwtUtil: JwtUtil
) {

    @PostMapping("/register")
    fun register(@RequestBody user: User): Mono<ResponseEntity<String?>> {
        return userService.saveUser(user)
            .map {
                ResponseEntity.ok(
                    "User registered successfully"
                )
            }
            .onErrorResume {
                Mono.just(
                    ResponseEntity.badRequest().body("Registration failed")
                )
            }
    }

    @PostMapping("/login")
    fun login(@RequestBody user: User): Mono<ResponseEntity<String>> {
        return userService.findByUsername(user.username)
            .flatMap { userDetails: UserDetails ->
                if (userDetails.password == user.password) {
                    val token: String = jwtUtil.generateToken(user.username)
                    return@flatMap Mono.just<ResponseEntity<String>>(
                        ResponseEntity.ok<String>(
                            token
                        )
                    )
                } else {
                    return@flatMap Mono.just<ResponseEntity<String>>(
                        ResponseEntity.status(401).body<String>("Invalid credentials")
                    )
                }
            }
    }
}