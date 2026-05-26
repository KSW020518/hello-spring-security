package kr.ac.hansung.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PasswordChangeDto {

    private String currentPassword;

    private String newPassword;

    private String confirmPassword;
}