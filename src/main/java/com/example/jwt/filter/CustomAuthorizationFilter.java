package com.example.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.jwt.domain.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
// từ CustomAuthenticationFilter ta được api bên phía client là access_token và refresh_token
//tiếp sau đó ta sẽ nhận từ bên phía client gửi lên server và kiểm tra token đó
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    @Override
//    dùng bộ lọc để xác định xem người dùng có quyền truy cập hay không
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

//        kiểm tra xem đây có phải là trường hợp đăng nhập không và nếu nó được đăng nhập bằng /api/login thì sẽ cho qua bộ lọc
        if(request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/token/refresh")){
            filterChain.doFilter(request,response); //vượt qua được bộ lọc
        }else {
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
        // kiểm tra xem giá trị trả về từ AUTHORIZATION có khác null và bắt đầu bằng Bearer không
                try{
//                  bỏ đi Bearer ở đầu authorizationHeader
                    String token = authorizationHeader.substring("Bearer ".length());
//                    sử dụng thuật toán để mã hóa
                    Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
//                xác minh JWT
                    JWTVerifier verifier = JWT.require(algorithm).build();
//                xác minh mã thông báo và mã nhận tên người dùng
                    DecodedJWT decodedJWT = verifier.verify(token);
                    String username = decodedJWT.getSubject();  // lấy ra tên người dùng
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);// lấy ra các quyền
//                    ở đây chúng ta không cần mật khẩu nữa vì người dùng đã được xác thực
                    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                    stream(roles).forEach(role ->{
                        authorities.add(new SimpleGrantedAuthority(role));
                    });
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
//                  xác định được tên người dùng, vai trò, quyền, xác định tài nguyên có thể truy cập
                    filterChain.doFilter(request, response);
                }catch (Exception exception){
                    log.error("Error logging in: {}", exception.getMessage());
                    response.setHeader("error", exception.getMessage());
                    response.setStatus(FORBIDDEN.value());
//                    response.sendError(FORBIDDEN.value());
                    Map<String, String> error = new HashMap<>();
                    error.put("error_message", exception.getMessage());
                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), error);
                }

            }else {
                filterChain.doFilter(request, response);
            }
        }
    }
}
