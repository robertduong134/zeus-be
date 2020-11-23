package vn.com.vetc.zeus.resources;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import vn.com.vetc.zeus.authencation.AuthenticationData;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class LoginResponse {

    private String accessToken;
    private String refreshToken;

    public static LoginResponse from(AuthenticationData authenticationData){
        return LoginResponse.builder()
                .accessToken(authenticationData.getAccessToken())
                .refreshToken(authenticationData.getRefreshToken())
                .build();
    }
}
