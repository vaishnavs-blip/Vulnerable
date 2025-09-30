package com.example.vulnapp.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.file.*;
import java.util.*;

@RestController
public class VulnController {

    @Autowired
    private JdbcTemplate jdbc;

    // ---------- Broken auth (hardcoded credentials + plaintext check) ----------
    // Vulnerable: Hardcoded admin credentials and plain-text check
    @PostMapping("/login")
    public Map<String, Object> login(@RequestParam String username, @RequestParam String password, HttpServletResponse resp) {
        Map<String, Object> r = new HashMap<>();
        if ("admin".equals(username) && "password".equals(password)) {
            // naive "session" via header (insecure)
            resp.setHeader("X-Auth-Token", "insecure-token-123");
            r.put("status", "ok");
            r.put("token", "insecure-token-123");
        } else {
            r.put("status", "invalid");
        }
        return r;
    }

    // ---------- SQL Injection endpoint ----------
    // Vulnerable: using string concatenation for SQL (classic SQLi)
    @GetMapping("/user")
    public List<Map<String, Object>> getUserByName(@RequestParam String name) {
        // INTENTIONALLY vulnerable SQL concatenation
        String sql = "SELECT id, username, email FROM users WHERE username = '" + name + "'";
        return jdbc.queryForList(sql);
    }

    // ---------- Reflected XSS ----------
    // Vulnerable: returns user-supplied input without encoding
    @GetMapping("/greet")
    public String greet(@RequestParam(defaultValue = "guest") String name) {
        // Reflected XSS: returns raw name directly into response body
        return "<html><body><h1>Hello " + name + "</h1></body></html>";
    }

    // ---------- File upload (no validation) ----------
    // Vulnerable: accepts any file, stores with original filename (no sanitization)
    @PostMapping("/upload")
    public Map<String, Object> upload(@RequestParam("file") MultipartFile file) throws IOException {
        Map<String, Object> r = new HashMap<>();
        Path uploads = Paths.get(System.getProperty("java.io.tmpdir"), "vuln-uploads");
        Files.createDirectories(uploads);
        // Vulnerable: uses original filename directly -> directory traversal risk
        Path target = uploads.resolve(file.getOriginalFilename());
        try (InputStream in = file.getInputStream()) {
            Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
        }
        r.put("saved", target.toString());
        return r;
    }

    // ---------- Insecure file download (IDOR / directory traversal) ----------
    // Vulnerable: path parameter trusted directly
    @GetMapping("/download")
    public ResponseEntity<?> download(@RequestParam("file") String filename) throws IOException {
        Path uploads = Paths.get(System.getProperty("java.io.tmpdir"), "vuln-uploads");
        Path target = uploads.resolve(filename).normalize();
        // NOTE: intentionally missing security checks to demonstrate traversal / IDOR
        if (!Files.exists(target)) {
            return ResponseEntity.status(404).body("Not found");
        }
        InputStreamResource resource = new InputStreamResource(Files.newInputStream(target));
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + target.getFileName().toString() + "\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(resource);
    }

    // ---------- Simple search that echoes query (for scanners) ----------
    // Helps scanners find reflected content and echo parameters
    @GetMapping("/search")
    public String search(@RequestParam(defaultValue = "") String q) {
        // Reflect param back — another reflected XSS surface
        return "<html><body>Search results for: " + q + "</body></html>";
    }

    // ---------- Health / info ----------
    @GetMapping("/info")
    public Map<String, Object> info(HttpServletRequest req) {
        Map<String, Object> r = new HashMap<>();
        r.put("serverTime", new Date().toString());
        r.put("remoteAddr", req.getRemoteAddr());
        return r;
    }
}