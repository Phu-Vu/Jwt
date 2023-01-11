package com.example.jwt.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.jwt.domain.Role;
import com.example.jwt.domain.User;
import com.example.jwt.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserResource {
    private final UserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getUsers(){

        return ResponseEntity.ok().body(userService.getUser());
//        ok ở đây là biểu hiện của 200 khi gọi api
    }

    @PostMapping("/user/save")
    public ResponseEntity<User> saveUser(@RequestBody User user){

        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveUser(user));
//        do khi gọi post có thể là 201 nên ta đổi sang created
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role> saveRole(@RequestBody Role role){

        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping("/role/addToUser")
    public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserForm form){
        userService.addRoleToUser(form.getUsername(), form.getRoleName());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
            // kiểm tra xem giá trị trả về từ AUTHORIZATION có khác null và bắt đầu bằng Bearer không
            try{
//                bỏ đi Bearer ở đầu authorizationHeader
                String refresh_token = authorizationHeader.substring("Bearer ".length());
//                sử dụng thuật toán để mã hóa
                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
//                xác minh JWT
                JWTVerifier verifier = JWT.require(algorithm).build();

//                xác minh mã thông báo và mã nhận tên người dùng
                DecodedJWT decodedJWT = verifier.verify(refresh_token);
                String username = decodedJWT.getSubject();  // lấy ra tên người dùng
                User user = userService.getUser(username);
//                ở đây chúng ta không cần mật khẩu nữa vì người dùng đã được xác thực
                String access_token = JWT.create()
                        .withSubject(user.getUsername())    //ở đây ta có thể getId -  dùng để nhận biết người dùng nào thôi
                        .withExpiresAt(new Date(System.currentTimeMillis() + 10*60*1000))    //xét hết hạn của refresh_token với thời gian là mili giây
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                        .sign(algorithm);

//        làm mới mã thông báo khi thông báo cũ hết hạn
//        ở đây với mã access_token sẽ được dùng để gửi thông báo, call api nhưng do nó chỉ có giới hạn là 1 ngày
//        nên khi mã access_token hết, để tránh việc người dùng phải đăng nhập lại thì ta sẽ dùng refresh_token, refresh_token sẽ có thời gian lâu hơn
//        vì sao ko dùng refresh_token thay cho access_token luôn? Do tính bảo mật, nếu cta để lộ access_token thì họ sẽ toàn quyền với tài khoản đó
//        refresh_token nên lưu ở cookie và không để lộ ra ở client

//        cách 2(nên dùng): gửi về header và cả api
                Map<String, String> tokens = new HashMap<>();
                tokens.put("access_token", access_token);
                tokens.put("refresh_token", refresh_token);
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);

            }catch (Exception exception){
                response.setHeader("error", exception.getMessage());
                response.setStatus(FORBIDDEN.value());
//                    response.sendError(FORBIDDEN.value());
                Map<String, String> error = new HashMap<>();
                error.put("error_message", exception.getMessage());
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);
            }

        }else {
            throw new RuntimeException("Refresh token is missing");
        }
    }

}

@Data
class RoleToUserForm {
    private String username;
    private String roleName;
}
