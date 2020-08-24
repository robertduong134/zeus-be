package vn.com.vetc.zeus.resources;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;
import vn.com.vetc.zeus.authencation.AuthenticationService;
import vn.com.vetc.zeus.authencation.SignInData;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthenticationController {

    @Autowired
    AuthenticationService authenticationService;

    @PostMapping(value = "/signin")
    public ResponseEntity<SignInResponse> signIn(@RequestBody SignInRequest signInRequest){
        SignInData signInData = authenticationService.signIn(signInRequest.getUsername(), signInRequest.getPassword());
        return ResponseEntity.ok(SignInResponse.from(signInData));
    }


}
