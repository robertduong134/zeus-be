package vn.com.vetc.zeus.authencation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import vn.com.vetc.zeus.security.jwt.JwtService;
import vn.com.vetc.zeus.security.jwt.JwtTokenData;

@Service
public class AuthenticationService {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationService.class);

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    JwtService jwtService;

    public SignInData signIn(String username, String password){
        log.debug("Request sign in from user: {}", username);
        Authentication authentication = null;
        try {
            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }catch (BadCredentialsException e) {
            e.printStackTrace();
            log.error("Sign in failed username: {}", username);
            throw e;
        }catch (LockedException e){
            e.printStackTrace();
            log.error("Account locked username: {}", username);
            throw e;
        }

        JwtTokenData jwtTokenData = jwtService.generateToken(username);

        return SignInData.builder()
                .jwtAccessToken(jwtTokenData.getJwtAccessToken())
                .jwtRefreshToken(jwtTokenData.getJwtRefreshToken())
                .build();
    }

}
