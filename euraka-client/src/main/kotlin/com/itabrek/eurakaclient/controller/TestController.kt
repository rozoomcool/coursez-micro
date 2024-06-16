package com.itabrek.eurakaclient.controller

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("main")
class TestController {

    @GetMapping("/test")
    fun test(): String = "Assalam Alaykum"
}