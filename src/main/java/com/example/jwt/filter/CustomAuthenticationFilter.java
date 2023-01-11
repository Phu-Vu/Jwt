package com.example.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
// class dùng để lấy username và password người dùng nhập sau đó xác thực người dùng xem đúng ko
// tiếp theo sẽ trả về cho người dùng api access_token và refresh_token
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    //    xác thực người dùng khi đăng nhập
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("Username is: {}",username);
        log.info("Password is: {}",password);
//        truyền username và password vào mã thông báo
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);

//        dùng authenticationManager để xác thực người dùng đang đăng nhập với thông tin trên
        return authenticationManager.authenticate(authenticationToken);
    }

//    xác thực thành công, được gọi khi đăng nhập thành công và sẽ gửi đến phía client
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {

//        User này là User của thư viện, hàm này sẽ trả về đối tượng là người dùng đã đăng nhập thành công
        User user = (User)authentication.getPrincipal();
//        tạo thuật toán
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
//        tạo biến chứa mã thông báo mới
        String access_token = JWT.create()
                        .withSubject(user.getUsername())    //ở đây ta có thể getId -  dùng để nhận biết người dùng nào thôi
                        .withExpiresAt(new Date(System.currentTimeMillis() + 10*60*1000))    //xét hết hạn của token với thời gian là mili giây
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);

//        làm mới mã thông báo khi thông báo cũ hết hạn
//        ở đây với mã access_token sẽ được dùng để gửi thông báo, call api nhưng do nó chỉ có giới hạn là 1 ngày
//        nên khi mã access_token hết, để tránh việc người dùng phải đăng nhập lại thì ta sẽ dùng refresh_token, refresh_token sẽ có thời gian lâu hơn
//        vì sao ko dùng refresh_token thay cho access_token luôn? Do tính bảo mật, nếu cta để lộ access_token thì họ sẽ toàn quyền với tài khoản đó
//        refresh_token nên lưu ở cookie và không để lộ ra ở client
        String refresh_token = JWT.create()
                        .withSubject(user.getUsername())    //ở đây ta có thể getId -  dùng để nhận biết người dùng nào thôi
                        .withExpiresAt(new Date(System.currentTimeMillis() + 30*60*1000))    //xét hết hạn của token với thời gian là mili giây
                        .withIssuer(request.getRequestURL().toString())
                        .sign(algorithm);

//        cách 1: chỉ gửi về phần header không có api
//        response.setHeader("access_token", access_token);
//        response.setHeader("refresh_token", refresh_token);

//        cách 2(nên dùng): gửi về header và cả api
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", access_token);
        tokens.put("refresh_token", refresh_token);
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }
}
