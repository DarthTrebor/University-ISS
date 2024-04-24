package com.example.sales_agents_backend.service;

import com.example.sales_agents_backend.domain.dto.UserResponseDTO;
import com.example.sales_agents_backend.domain.dto.UserRequestDTO;
import com.example.sales_agents_backend.domain.entities.User;
import com.example.sales_agents_backend.domain.enums.RoleType;
import com.example.sales_agents_backend.exceptions.ResourceAlreadyExistsException;
import com.example.sales_agents_backend.exceptions.ResourceNotFoundException;
import com.example.sales_agents_backend.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(password.getBytes());
            byte[] hashedBytes = md.digest();
            StringBuilder stringBuilder = new StringBuilder();
            for (byte b : hashedBytes) {
                stringBuilder.append(String.format("%02x", b));
            }
            return stringBuilder.toString();
        } catch (NoSuchAlgorithmException e) {
            // Handle exception
            e.printStackTrace();
            return null;
        }
    }

    public UserResponseDTO authorizeUser(String email, String password) {
        String hashedPassword = hashPassword(password);

        User user = userRepository.findByEmailAndPassword(email, hashedPassword)
                .orElseThrow(() -> new ResourceNotFoundException("Credentials don't match any user in the system"));

        return new UserResponseDTO(user.getId(), user.getName(), user.getEmail(), user.getPassword(), user.getRole());
    }

    public UserResponseDTO authorizeAdmin(String email, String password) {
        String hashedPassword = hashPassword(password);

        User admin = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Credentials don't match any user in the system"));

        if (admin.getRole() != RoleType.ADMIN) {
            throw new RuntimeException("User is not an admin");
        }
        if (!admin.getPassword().equals(hashedPassword)) {
            throw new ResourceNotFoundException("Credentials don't match any user in the system");
        }
        return new UserResponseDTO(admin.getId(), admin.getName(), admin.getEmail(), admin.getPassword(), admin.getRole());
    }

    public UserResponseDTO registerUser(UserRequestDTO user) throws NoSuchAlgorithmException {
        Optional<User> existingUser = userRepository.findByEmail(user.email());
        if (existingUser.isPresent()) {
            throw new ResourceAlreadyExistsException("Email already in use by another user");
        }

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(user.password().getBytes());
        byte[] hashedBytes = md.digest();
        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : hashedBytes) {
            stringBuilder.append(String.format("%02x", b));
        }
        User newUser = new User(user.name(), user.email(), stringBuilder.toString(), user.role());
        userRepository.save(newUser);
        return new UserResponseDTO(newUser.getId(), newUser.getName(), newUser.getEmail(), newUser.getPassword(), newUser.getRole());
    }

}
