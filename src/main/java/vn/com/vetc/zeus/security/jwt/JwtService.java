package vn.com.vetc.zeus.security.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    @Autowired
    JwtProvider jwtProvider;

    public JwtTokenData generateToken(String username){
        String jwtAccessToken = jwtProvider.generateAccessTokenRSA(username);
        String jwtRefreshToken = jwtProvider.generateRefreshToken(username);
        return JwtTokenData.builder().jwtAccessToken(jwtAccessToken).jwtRefreshToken(jwtRefreshToken).build();
    }

    public Integer getJwtExpiration(){
        return jwtProvider.getJwtExpiration();
    }

    public Integer getJwtRefreshExpiration(){
        return jwtProvider.getJwtRefreshExpiration();
    }
}
