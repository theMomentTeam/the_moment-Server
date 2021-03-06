package com.moment.the.table.service;

import com.moment.the.exceptionAdvice.exception.GoodsNotCancelException;
import com.moment.the.exceptionAdvice.exception.NoPostException;
import com.moment.the.table.TableDomain;
import com.moment.the.table.dto.TableDto;
import com.moment.the.table.dto.TableViewDto;
import com.moment.the.table.repository.TableRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
@Service
public class TableService {
    private final TableRepository tableRepository;

    // 작성하기.
    @Transactional
    public TableDomain write(TableDto tableDto){
        return tableRepository.save(tableDto.toEntity());
    }

    // Top 30 보여주기.
    public List<TableViewDto> top30View() {
        return tableRepository.tableViewTopBy(PageRequest.of(0,30));
    }

    // 전체 페이지 보여주기.
    public List<TableViewDto> viewAll(){
        return tableRepository.tableViewAll();
    }

    // 전체 게시물 개수 보여주기.
    public Long amountUncomfortableView(){
        return tableRepository.amountUncomfortable();
    }

    // 프로젝트 시작 이후 날짜 보여주기.
    public int dateSinceProjectStart(){
        return calculateAfterDate();
    }

    // 좋아요 수 증가.
    @Transactional
    public void goods(Long boardIdx){
        TableDomain tableDomain = tableRepository.findByBoardIdx(boardIdx).orElseThrow(NoPostException::new);
        tableDomain.updateGoods(tableDomain.getGoods()+1);
    }

    // 좋아요 수 감소.
    @Transactional
    public void cancelGood(Long boardIdx) {
        TableDomain tableDomain = tableRepository.findByBoardIdx(boardIdx).orElseThrow(NoPostException::new);
        int goodsResult = tableDomain.getGoods() - 1;

        if(goodsResult > -1) {//좋야요가 양수일때
            tableDomain.updateGoods(goodsResult);
        }else{
            throw new GoodsNotCancelException();
        }
    }

    // day 수 계산하기
    public static int calculateAfterDate(){
        /**
         * today: 오늘 날짜
         * theMomentStart: the-moment 시작 날짜
         */
        LocalDate today = LocalDate.now();
        LocalDate theMomentStart = LocalDate.of(2021, 6, 7);

        // the_moment 프로젝트를 시작한 날짜 by 오늘의 날짜
        int period = (int) theMomentStart.until(today, ChronoUnit.DAYS);

        return period;
    }
}
