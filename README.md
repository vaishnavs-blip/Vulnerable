Vulnerable App — README
-----------------------

Run:
1. mvn clean package
2. java -jar target/vulnapp-0.0.1-SNAPSHOT.jar
3. Open http://localhost:8080 in a browser (index.html is served from /static)

H2 console: http://localhost:8080/h2-console
JDBC url: jdbc:h2:mem:vulndb
user: sa
password: (empty)

Safety:
- Run this only inside an isolated VM or container (no NAT to internet) or bind to localhost only.
- DO NOT expose to public networks.
- After testing, delete the VM/container.

Vulnerabilities intentionally included:
- Reflected XSS: /greet, /search
- SQL Injection: /user (query concatenation)
- Broken auth: /login (hardcoded / plaintext)
- Insecure file upload: /upload (no filename sanitization)
- Directory traversal / IDOR like behavior: /download (trusts filename parameter)
