package com.moment.the.admin.service;

import com.moment.the.admin.AdminDomain;
import com.moment.the.admin.dto.AdminDto;
import com.moment.the.admin.dto.SignInDto;
import com.moment.the.admin.repository.AdminRepository;
import com.moment.the.config.security.jwt.JwtUtil;
import com.moment.the.exceptionAdvice.exception.UserAlreadyExistsException;
import com.moment.the.exceptionAdvice.exception.UserNotFoundException;
import com.moment.the.util.RedisUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;


@Service
@RequiredArgsConstructor
public class AdminServiceImpl implements AdminService {

    private final AdminRepository adminRepository;
    private final PasswordEncoder passwordEncoder;
    private final RedisUtil redisUtil;
    private final JwtUtil jwtUtil;

    @Override
    public void signUp(AdminDto adminDto) {
        if(adminRepository.findByAdminId(adminDto.getAdminId()) != null){
            throw new UserAlreadyExistsException();
        }
        adminDto.setAdminPwd(passwordEncoder.encode(adminDto.getAdminPwd()));
        adminRepository.save(adminDto.toEntity());
    }

    @Override
    public Map<String, String> loginUser(String id, String password) {
        // 아이디 검증
        AdminDomain adminDomain = adminRepository.findByAdminId(id);
        if (adminDomain == null) throw new UserNotFoundException();
        // 비밀번호 검증
        boolean passwordCheck = passwordEncoder.matches(password, adminDomain.getPassword());
        if (!passwordCheck) throw new UserNotFoundException();

        final String accessToken = jwtUtil.generateAccessToken(adminDomain.getAdminId());
        final String refreshJwt = jwtUtil.generateRefreshToken(adminDomain.getAdminId());
        // token 만료 기간 설정
        redisUtil.setDataExpire(refreshJwt, adminDomain.getUsername(), JwtUtil.REFRESH_TOKEN_EXPIRATION_TIME);
        Map<String ,String> map = new HashMap<>();
        map.put("id", adminDomain.getAdminId());
        map.put("accessToken", accessToken); // accessToken 반환
        map.put("refreshToken", refreshJwt); // refreshToken 반환

        return map;
    }

    // 로그아웃
    @Override
    public void logout() {
        String userEmail = this.getUserEmail();
        redisUtil.deleteData(userEmail);
    }

    @Override
    public void withdrawal(SignInDto signInDto) throws Exception {
        // 로그인 된 이메일과 내가 삭제하려는 이메일이 같을 때.
        if (getUserEmail().equals(signInDto.getAdminId())) {
            AdminDomain adminDomain = adminRepository.findByAdminId(signInDto.getAdminId());
            adminRepository.delete(adminDomain);
        } else {
            throw new Exception("로그인 후 이용해주세요.");
        }
    }

    //현재 로그인 된 사용자의 ID를 Return
    static public String getUserEmail() {
        String userEmail;
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if(principal instanceof UserDetails) {
            userEmail = ((UserDetails) principal).getUsername();
        } else {
            userEmail = principal.toString();
        }
        return userEmail;
    }
}
