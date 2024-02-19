package com.huyvu.springsecurityjwt.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class LazySecurityContextProviderFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain filterChain)
            throws ServletException, IOException {
        var context = SecurityContextHolder.getContext();
        SecurityContextHolder.setContext(new LazyJwtSecurityContextProvider(req, res, context));
        filterChain.doFilter(req, res);
    }

    static class LazyJwtSecurityContextProvider implements SecurityContext {

        private final SecurityContext securityCtx;

        private final HttpServletRequest req;
        private final HttpServletResponse res;

        LazyJwtSecurityContextProvider(HttpServletRequest req, HttpServletResponse res, SecurityContext securityCtx) {
            this.securityCtx = securityCtx;
            this.req = req;
            this.res = res;
        }


        @Override
        public Authentication getAuthentication() {
            if (securityCtx.getAuthentication() == null || securityCtx.getAuthentication() instanceof AnonymousAuthenticationToken) {
                try {
                    var jwtToken = SecurityUtils.getTokenFromRequest(this.req);
                    var jwtTokenResult = SecurityUtils.validateJWTToken(jwtToken);
                    var authToken = new PreAuthenticatedAuthenticationToken(jwtTokenResult, null, jwtTokenResult.getAuthorities());
//                    authToken.setAuthenticated(false);
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
                    securityCtx.setAuthentication(authToken);
                } catch (Exception e) {
                    log.debug("Cannot get authentication context: " + e.getMessage());
                }

            }

            return securityCtx.getAuthentication();
        }


        @Override
        public void setAuthentication(Authentication authentication) {
            securityCtx.setAuthentication(authentication);
        }
    }


}