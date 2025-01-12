# PasswordManagerCPP

A secure password manager written in C++ that encrypts your passwords using AES-256-CBC encryption. Store and retrieve your passwords safely with this command-line utility.

---

## Features
- Secure encryption using AES-256-CBC.
- Passwords stored in an encrypted format.
- Simple CLI interface for adding and viewing passwords.

---

## Requirements
- A C++17 compatible compiler (e.g., GCC, Clang, MSVC).
- OpenSSL library.

---

## Setup and Installation

### Linux (Debian/Ubuntu-based)
```bash
sudo apt update
sudo apt install -y g++ make libssl-dev
```

### Linux (Arch-based)
```bash
sudo pacman -Syu
gcc make openssl
```

### Fedora (or RPM-based systems)
```bash
sudo dnf install -y gcc make openssl-devel
```

### macOS
1. Install [Homebrew](https://brew.sh/) if not already installed.
2. Install dependencies:
   ```bash
   brew install gcc openssl
   ```

### Windows
1. Install [MSYS2](https://www.msys2.org/) or [Visual Studio Community Edition](https://visualstudio.microsoft.com/).
2. If using MSYS2:
   ```bash
   pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl
   ```

---

## Compilation

### Generic Compilation Command
```bash
g++ -std=c++17 -o PasswordManager PasswordManager.cpp -lssl -lcrypto
```

### For Linux (Debian/Ubuntu/Fedora/Arch-based)
```bash
g++ -std=c++17 -o PasswordManager PasswordManager.cpp -lssl -lcrypto
```

### For macOS
```bash
g++ -std=c++17 -o PasswordManager PasswordManager.cpp -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lssl -lcrypto
```

### For Windows (MSYS2)
```bash
g++ -std=c++17 -o PasswordManager.exe PasswordManager.cpp -lssl -lcrypto
```

---

## Usage

1. Run the compiled program:
   ```bash
   ./PasswordManager   # or PasswordManagerCPP.exe on Windows
   ```

---

## Options
- `view`: View stored usernames and their decrypted passwords in a table.
- `add`: Add a new username and password to the storage.
- `q`: Quit the application.

---

## Example

1. Run the program:
   ```bash
   ./PasswordManager
   ```
2. Add a password:
   ```
   Enter username: example_user
   Enter password: secure_password123
   Password for account 'example_user' has been saved securely.
   ```
3. View passwords:
   ```
   +-------------------+-------------------+
   | Username          | Password          |
   +-------------------+-------------------+
   | example_user      | secure_password123|
   +-------------------+-------------------+
   ```

---

## File Structure
- **key.bin**: Stores the encryption key (auto-generated).
- **passwords.txt**: Stores the encrypted passwords.

---

## Security Note
- Keep `key.bin` secure. Losing it means you cannot decrypt your saved passwords.
- Do not share `passwords.txt` without also sharing `key.bin` (though sharing both is discouraged).

---

## License
This project is licensed under the MIT License. See `LICENSE` for details.
