# TrustVault – Secure Document Sharing with a Real Audit Trail

## Project Overview
TrustVault is a secure document-sharing web application developed using Python Flask. It allows users to upload, store, and share PDF documents securely with controlled access.

## Features
- User Registration and Login
- Password Hashing
- Secure PDF Upload
- Private Document Storage
- Owner-Only Document Access
- Read-Only Document Sharing
- Revoke All Access
- Server-Side Download Authorization
- SHA-256 Hash-Linked Audit Logs
- Admin Dashboard
- Admin-Only Access Control

## Technologies Used
- Python
- Flask
- SQLite
- HTML
- CSS
- SHA-256 Hashing

## Database
SQLite is used to store user information, document details, sharing permissions, and audit logs.

## Security
- Passwords are stored using hashing.
- Uploaded PDFs are stored privately.
- Unauthorized document access is restricted.
- Document downloads require server-side authorization.
- Audit logs maintain a hash-linked record of activities.

## Project Purpose
The main goal of TrustVault is to provide secure document sharing with access control and a verifiable audit trail.

## Developer
Developed as a Final Year B.Tech Project.