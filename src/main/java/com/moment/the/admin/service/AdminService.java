package com.moment.the.admin.service;

import com.moment.the.admin.dto.AdminDto;
import com.moment.the.admin.dto.SignInDto;

import java.util.Map;

public interface AdminService {
    void signUp(AdminDto adminDto) throws Exception;
    Map<String, String> loginUser(String id, String password) throws Exception;
    void logout();
    void withdrawal(SignInDto SignInDto) throws Exception;
}
