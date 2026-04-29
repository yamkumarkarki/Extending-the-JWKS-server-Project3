# JWKS Server Project 3

## Overview

This project enhances a JWKS authentication server with improved security and user management features.

The server supports RSA key generation, JWT authentication, JWKS key publishing, user registration, AES encryption of private keys, authentication request logging, and rate limiting.

## Features

- RSA private/public key generation
- JWKS endpoint
- JWT authentication endpoint
- AES encrypted private keys in SQLite
- User registration endpoint
- Secure password generation using UUIDv4
- Argon2 password hashing
- Authentication request logging
- Time-window rate limiting for `/auth`

## Requirements

- Python 3
- Flask
- PyJWT
- Cryptography
- Argon2-CFFI
- Pytest
- Pytest-Cov

## Installation

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate