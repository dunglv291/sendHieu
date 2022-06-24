package com.example.demologinwithauthentication.login.ulti;

import io.jsonwebtoken.ExpiredJwtException;
import com.example.demologinwithauthentication.login.service.UserService;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.SignatureException;
import java.sql.Timestamp;
import java.time.LocalDateTime;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {
    @Autowired
    private UserService jwtUserDetailsService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private JwtConfig jwtConfig;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        final String requestTokenHeader = request.getHeader(jwtConfig.getAuthorizationHeader());

        String username = null;
        String jwtToken = null;
        // JWT Token is in the form "Bearer token". Remove Bearer word and get
        // only the Token
        if (requestTokenHeader != null && requestTokenHeader.startsWith(jwtConfig.getTokenPrefix())) {
            jwtToken = requestTokenHeader.substring(7);
            try {
                username = jwtTokenUtil.getUsernameFromToken(jwtToken);
            } catch (IllegalArgumentException e) {
                System.out.println("Unable to get JWT Token");
            } catch (ExpiredJwtException e) {

                String isRefreshToken = request.getHeader("isRefreshToken");
                String requestURL = request.getRequestURL().toString();
                // allow for Refresh Token creation if following conditions are true.
                if (isRefreshToken != null && isRefreshToken.equals("true") && requestURL.contains("refreshtoken")) {
                    allowForRefreshToken(e, request);
                } else
                    request.setAttribute("exception", e);

                System.out.println(e.getMessage());

                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                response.getOutputStream().print(responseErrorMessage("Expired JWT Token", request.getRequestURI().substring(request.getContextPath().length())));
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            } catch (MalformedJwtException | UnsupportedJwtException ex){
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                response.getOutputStream().print(responseErrorMessage("Invalid JWT Token", request.getRequestURI().substring(request.getContextPath().length())));
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            }


        } else {
            logger.warn("JWT Token does not begin with Bearer String");
        }

        // Once we get the token validate it.
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = this.jwtUserDetailsService.loadUserByUsername(username);

            // if token is valid configure Spring Security to manually set
            // authentication
            if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {

                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                usernamePasswordAuthenticationToken
                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // After setting the Authentication in the context, we specify
                // that the current user is authenticated. So it passes the
                // Spring Security Configurations successfully.
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }

        chain.doFilter(request, response);
    }

    private void allowForRefreshToken(ExpiredJwtException ex, HttpServletRequest request) {

        // create a UsernamePasswordAuthenticationToken with null values.
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                null, null, null);
        // After setting the Authentication in the context, we specify
        // that the current user is authenticated. So it passes the
        // Spring Security Configurations successfully.
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        // Set the claims so that in controller we will be using it to create
        // new JWT
        request.setAttribute("claims", ex.getClaims());

    }

    public String responseErrorMessage(String errorString, String path) {

        String message = "";

        message += String.format("{ \"timestamp\": \"%s\", \n", Timestamp.valueOf(LocalDateTime.now()).toString());
        message += " \"status\": 401, \n";
        message += String.format(" \"error\": \"%s\", \n", errorString);
        message += String.format(" \"path\": \"%s\" }", path);

        return message;

    }
}
