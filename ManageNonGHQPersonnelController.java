package com.authorization.crewservice.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/manage-non-ghq-personnel")
public class ManageNonGHQPersonnelController {

    @PostMapping("/edit-personnel-details")
    public List<String> editPersonnelDetails() {
         return Arrays.asList("1", "2");
     }


}

