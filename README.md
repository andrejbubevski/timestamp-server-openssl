# 📜 Flask RFC3161 Timestamp Authority (TSA)

A simple RFC3161-compliant Timestamp Authority (TSA) server built with Flask and SQLAlchemy. This project allows users to upload files, generate trusted timestamps, store and verify timestamp tokens, and interact with the system via both web and API.

## ✨ Features

- Upload and timestamp files using SHA256.
- RFC3161-compliant timestamp token generation.
- Web dashboard to browse and verify timestamps.
- API endpoint for verification.
- Built-in certificate signing using `cryptography` and `asn1crypto`.
- SQLite database with SQLAlchemy for storing timestamp entries.
