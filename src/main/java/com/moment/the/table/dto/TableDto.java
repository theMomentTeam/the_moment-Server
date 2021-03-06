package com.moment.the.table.dto;

import com.moment.the.table.TableDomain;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import javax.validation.constraints.NotBlank;


@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TableDto {
    @NotBlank
    private String content;

    public TableDomain toEntity(){
        return TableDomain.builder()
                .content(this.content)
                .build();
    }
}
