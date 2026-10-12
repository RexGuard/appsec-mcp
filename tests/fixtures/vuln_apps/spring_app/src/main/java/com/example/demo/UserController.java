package com.example.demo;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.sql.DataSource;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserController {
    private final DataSource dataSource;

    public UserController(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @GetMapping("/users")
    public String findUser(@RequestParam String name) throws Exception {
        try (Connection conn = dataSource.getConnection(); Statement stmt = conn.createStatement()) {
            ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
            return rs.next() ? rs.getString("email") : "not found";
        }
    }

    @PostMapping("/import")
    public String importProfile(@RequestBody byte[] body) throws Exception {
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(body))) {
            Object profile = in.readObject();
            return "imported " + profile;
        }
    }
}
