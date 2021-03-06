package com.moment.the.improvement.service;

import com.moment.the.admin.AdminDomain;
import com.moment.the.admin.repository.AdminRepository;
import com.moment.the.admin.service.AdminServiceImpl;
import com.moment.the.exceptionAdvice.exception.AccessNotFoundException;
import com.moment.the.exceptionAdvice.exception.UserNotFoundException;
import com.moment.the.improvement.ImprovementDomain;
import com.moment.the.improvement.dto.ImprovementDto;
import com.moment.the.improvement.dto.ImprovementViewAllDto;
import com.moment.the.improvement.repository.ImprovementRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ImprovementService {
    private final ImprovementRepository improvementRepository;
    private final AdminRepository adminRepository;

    // Create improvement.
    @Transactional
    public ImprovementDomain save(ImprovementDto improvementDto){
        try {
            AdminDomain adminDomain = adminRepository.findByAdminId(AdminServiceImpl.getUserEmail());
            return improvementRepository.save(improvementDto.ToEntity(adminDomain));
        } catch (UserNotFoundException e){
            throw new UserNotFoundException();
        }
    }

    // Read improvement.
    public List<ImprovementViewAllDto> read(){
        ModelMapper modelMapper = new ModelMapper();
        return improvementRepository.findAllByOrderByImproveIdxDesc().stream()
                .map(m -> modelMapper.map(m, ImprovementViewAllDto.class))
                .collect(Collectors.toList());
    }

    // Update improvement.
    @Transactional
    public void update(ImprovementDto improvementDto, Long improveIdx){
        // 개선 사례 가져오기
        ImprovementDomain improvementDomain = improvementRepository.findByImproveIdx(improveIdx);
        if(improvementDomain.getAdminDomain().getAdminId().equals(AdminServiceImpl.getUserEmail())){
            improvementDomain.update(improvementDto);
        } else {
            throw new AccessNotFoundException();
        }
    }

    // Delete improvement.
    @Transactional
    public void delete(Long improveIdx){
        ImprovementDomain selectImprove = improvementRepository.findByImproveIdx(improveIdx);
        if(selectImprove.getAdminDomain().getAdminId().equals(AdminServiceImpl.getUserEmail())){
            improvementRepository.delete(selectImprove);
        } else {
            throw new AccessNotFoundException();
        }
    }
}
