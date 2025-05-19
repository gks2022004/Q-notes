# Quantum Notes
A quantum-secure note-taking application with advanced encryption for protecting your sensitive information.

## Architecture
![image](https://github.com/user-attachments/assets/aff29d0d-4e04-45ee-8379-f1e7e5c96560)


## Download from here:
* [here](https://github.com/gks2022004/Q-NOTES/releases/download/v1.0.1/quantum-notes.exe)

## Features

- **Post-Quantum Security** - Uses Kyber-768 encryption (NIST-approved PQC algorithm) to protect against future quantum computer threats
- **End-to-end Encryption** - All notes are encrypted before leaving your device
- **Local Storage** - Notes are stored securely on your machine, not in the cloud
- **Password Protection** - Strong authentication using Argon2id password hashing
- **User-friendly Interface** - Built with Fyne toolkit for a clean, cross-platform experience
- **Offline Capability** - Works without an internet connection

## Installation

### Prerequisites

- Go 1.18 or higher
- A C compiler (for SQLite support)
- Git

### Building from source

1. Clone the repository
```bash
git clone https://github.com/gks2022004/Q-NOTES.git
cd quantum-notes
```
2. Install dependencies
```bash
go mod download
```
3. Run the applicaton
```bash
go run main.go
```

## Usage
### Creating an Account

* Launch the application
* Enter a username and password
* Click "Register" to create your account

### Managing Notes

* Create a new note: Click "New" and enter title and content
* Save a note: Click "Save" after entering content
* Edit a note: Select a note from the list to edit it
* Delete a note: Select a note and click "Delete"
* Import a note: Click "Import" and select a .qsnote file

### Security Details
- Quantum Notes implements multiple layers of security:
* Authentication: Argon2id password hashing (winner of the Password Hashing Competition)
* Key Exchange: CRYSTALS-Kyber algorithm (NIST post-quantum cryptography standard)
* Encryption: AES-256-GCM for symmetric encryption of note contents
* File Protection: Encrypted files have the .qsnote extension and can only be decrypted with the correct key

### Technical Implementation

* User private keys are encrypted with a key derived from the password hash
* Each note is encrypted with a session key derived from the password hash
* Notes are stored as encrypted files with references in an SQLite database

### ScreenShots:
![image](https://github.com/user-attachments/assets/a4068727-9713-404d-ae25-4d71cde92cd8)

![image](https://github.com/user-attachments/assets/ac5ed9c1-6a38-4a8d-b024-4dd0c575c394)

![image](https://github.com/user-attachments/assets/39bafd81-77ca-451f-bc3f-82f6a079b59d)

![image](https://github.com/user-attachments/assets/5244a56d-4f88-4eaa-bc09-31dcb21f7f59)




### Dependencies

* [Fyne](https://fyne.io/) - Cross-platform GUI toolkit
* [Circl](https://github.com/cloudflare/circl) - Cloudflare's cryptographic library with post-quantum algorithms
* [go-sqlite3](https://github.com/mattn/go-sqlite3) - SQLite database driver
* [Argon2](https://pkg.go.dev/golang.org/x/crypto/argon2) - Password hashing algorithm

## Building for different platforms

### Windows
```bash
GOOS=windows GOARCH=amd64 go build -o quantum-notes.exe
```

### macOS
```bash
GOOS=darwin GOARCH=amd64 go build -o quantum-notes-mac
```

### Linux
```bash
GOOS=linux GOARCH=amd64 go build -o quantum-notes-linux
```

## Developed by: Gaurav Kumar Singh
