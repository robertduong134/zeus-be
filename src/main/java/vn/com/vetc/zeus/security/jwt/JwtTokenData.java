package vn.com.vetc.zeus.security.jwt;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class JwtTokenData {

    private String jwtAccessToken;
    private String jwtRefreshToken;
}
