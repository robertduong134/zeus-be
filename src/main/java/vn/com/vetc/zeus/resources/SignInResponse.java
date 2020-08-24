package vn.com.vetc.zeus.resources;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import vn.com.vetc.zeus.authencation.SignInData;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class SignInResponse {

    private String jwtAccessToken;
    private String jwtRefreshToken;

    public static SignInResponse from(SignInData signInData){
        return SignInResponse.builder()
                .jwtAccessToken(signInData.getJwtAccessToken())
                .jwtRefreshToken(signInData.getJwtRefreshToken())
                .build();
    }
}
