# TrustVault – Threat Model

## 1. Purpose
This document identifies possible security threats to the TrustVault application.

## 2. Assets to Protect
- User account credentials
- Uploaded PDF documents
- Document sharing permissions
- Audit log records
- Database information

## 3. Possible Threats

### Unauthorized Access
An unauthorized user may try to access private documents.

Protection: Owner-only access checks and server-side authorization.

### Password Theft
Attackers may try to obtain user passwords.

Protection: Password hashing.

### Malicious File Upload
Users may attempt to upload invalid or harmful files.

Protection: PDF file validation and a 5 MB upload limit.

### Unauthorized Downloads
A user may try to download a document without permission.

Protection: Server-side download authorization.

### Audit Log Tampering
An attacker may try to modify audit records.

Protection: SHA-256 hash-linked audit logs.

### Admin Access Abuse
Normal users may try to access administrator features.

Protection: Admin-only access control.

## 4. Limitations
Hash-linked audit logs help detect changes but do not prevent every form of database tampering.

## 5. Conclusion
TrustVault uses multiple security measures to protect documents, control sharing, and maintain an audit trail.