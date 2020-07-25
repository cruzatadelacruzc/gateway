package com.example.gateway.web.rest;

import com.example.gateway.service.OAuth2AuthenticationService;
import com.example.gateway.web.rest.vm.LoginVM;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

@Slf4j
@RestController
@RequestMapping("/auth")
@AllArgsConstructor
public class AuthenticateResource {

    private final OAuth2AuthenticationService authenticationService;

    /**
     * Authenticates a user setting the access and refresh token cookies.
     *
     * @param loginVM object that store a user's credentials.
     * @param request the {@link HttpServletRequest} holding - among others - the headers passed from the client.
     * @param response the {@link HttpServletResponse} getting the cookies set upon successful authentication.
     * @return the {@link ResponseEntity} with status {@code 200 (OK)} and with body the access token
     * of the authenticated user, or with status with status {@code 400 (Bad Request)} if it fails to authenticate the user.
     */
    @PostMapping(value = "/login", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<OAuth2AccessToken> authorize(@Valid @RequestBody LoginVM loginVM,
                                                       HttpServletRequest request, HttpServletResponse response) {
        OAuth2AccessToken accessToken = authenticationService.authenticate(loginVM, request, response);
        return ResponseEntity.ok(accessToken);
    }

    /**
     * {@code POST /logout} : Logout current user deleting his cookies.
     *
     * @param request the {@link HttpServletRequest} holding - among others - the headers passed from the client.
     * @param response response the {@link HttpServletResponse} getting the cookies set upon successful authentication.
     * @return the {@link ResponseEntity} with status {@code 204 (Not Content)}.
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        log.debug("logging out user {}", SecurityContextHolder.getContext().getAuthentication().getName());
        authenticationService.logout(request,response);
        return ResponseEntity.noContent().build();
    }
}
