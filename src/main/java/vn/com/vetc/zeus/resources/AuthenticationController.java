package vn.com.vetc.zeus.resources;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;
import vn.com.vetc.zeus.authencation.AuthenticationService;
import vn.com.vetc.zeus.authencation.AuthenticationData;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthenticationController {

    @Autowired
    AuthenticationService authenticationService;

    @PostMapping(value = "/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest){
        AuthenticationData authenticationData = authenticationService.login(loginRequest.getUsername(), loginRequest.getPassword());
        return ResponseEntity.ok(LoginResponse.from(authenticationData));
    }


}
