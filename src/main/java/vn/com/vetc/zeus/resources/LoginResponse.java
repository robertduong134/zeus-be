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

    private String accessToken;
    private String refreshToken;

    public static SignInResponse from(SignInData signInData){
        return SignInResponse.builder()
                .accessToken(signInData.getAccessToken())
                .refreshToken(signInData.getRefreshToken())
                .build();
    }
}
