package com.example.jwt.service;

import com.example.jwt.domain.Role;
import com.example.jwt.domain.User;
import com.example.jwt.repo.RoleRepo;
import com.example.jwt.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@RequiredArgsConstructor
//hàm tạo đối số yêu cầu(như tạo rồi truyền contructor như bthg)
@Transactional
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        tìm người dùng theo tên, nếu ko có sẽ bắn ra 1 exception
        User user = userRepo.findByUsername(username);
        if(user == null){
            log.error("User not found in the database");
            throw new UsernameNotFoundException("User not found in the database");
        }else{
            log.info("User not found in the database: {}", username);

        }
//        lấy ra tất cả các quyền mà người dùng này có
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
    }

    @Override
    public User saveUser(User user) {
        log.info("Saving new user{} to the database", user.getName());
//        kiểu như sout, nó sẽ hiển thị trong phần nhật ký
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Saving new role{} to the database", role.getName());
        return roleRepo.save(role);
    }

    @Override
//    thêm quyền cho user đươc chỉ định
    public void addRoleToUser(String username, String roleName) {
        log.info("Adding role{} to user{}", roleName, username);
        User user = userRepo.findByUsername(username);
        Role role = roleRepo.findByName(roleName);
        user.getRoles().add(role);
    }

    @Override
    public User getUser(String username) {
        log.info("Fetching user{}", username);
        return userRepo.findByUsername(username);
    }

    @Override
    public List<User> getUser() {
        log.info("Fetching all users");
        return userRepo.findAll();
    }

}
