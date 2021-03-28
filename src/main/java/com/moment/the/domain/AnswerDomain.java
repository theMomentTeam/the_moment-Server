package com.moment.the.domain;

import com.sun.istack.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Table(name = "Answer")
@Entity
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AnswerDomain {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long answerIdx;

    @Column
    @NotNull
    private String answerContent;

    @ManyToOne(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinColumn(name = "tableIdx")
    private TableDomain tableDomain;

    @ManyToOne(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinColumn(name="adminId")
    private AdminDomain adminDomain;

    public void update(String answerContent){
        this.answerContent = answerContent;
    }

}
