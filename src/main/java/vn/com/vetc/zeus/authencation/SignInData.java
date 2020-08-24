package vn.com.vetc.zeus.authencation;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class SignInData {

    private String jwtAccessToken;
    private String jwtRefreshToken;

}
