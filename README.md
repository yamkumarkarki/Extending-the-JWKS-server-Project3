# 🔐 Extending the JWKS Server – Project 3

A secure JSON Web Key Set (JWKS) authentication server built with **Python**, **Flask**, and **SQLite**.  
This project extends a basic JWKS server by adding encryption, user management, logging, and rate limiting.

> Developed as part of **CSCE3550 – Foundations of Cybersecurity**

---

# 📌 Project Overview

This server provides secure JWT-based authentication and publishes public keys through a JWKS endpoint.

The project improves security by:

- Encrypting private keys before storing them in the database
- Adding user registration
- Hashing passwords using Argon2
- Logging authentication activity
- Preventing abuse with rate limiting

---

# 🚀 Features

### 🔑 Authentication & Keys
- RSA key pair generation  
- JWT token creation using RS256  
- JWKS public key publishing endpoint  

### 🔒 Security Enhancements
- AES-encrypted private keys in SQLite  
- Environment-variable secret management (`NOT_MY_KEY`)  
- Argon2 password hashing  

### 👤 User Management
- User registration endpoint  
- UUIDv4 secure password generation  

### 📊 Monitoring
- Authentication request logging  
- IP tracking and timestamps  

### ⚡ Protection
- Rate limiting (`10 requests / second`) on `/auth`

---

# 🛠️ Tech Stack

| Category | Technology |
|--------|------------|
| Language | Python |
| Framework | Flask |
| Database | SQLite |
| Auth | JWT (PyJWT) |
| Encryption | AES / Fernet |
| Password Hashing | Argon2 |
| Testing | Pytest |

---

# 📂 Project Structure

```text
Extending-the-JWKS-server-Project3/
├── app.py
├── requirements.txt
├── README.md
├── test_app.py
├── screenshots/
│   ├── gradebot-result.png
│   └── coverage-result.png
└── .gitignore

Results
<img width="744" height="165" alt="test-coverage" src="https://github.com/user-attachments/assets/d09746c5-518c-4c05-aa9b-9404e9b71819" />
<img width="847" height="447" alt="gradebot-result" src="https://github.com/user-attachments/assets/3cba264a-837d-4bf6-8e2a-827b0aa5967c" />

