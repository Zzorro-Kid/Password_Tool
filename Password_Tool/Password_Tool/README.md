# Password Tool

A versatile command-line utility for both generating secure passwords and hashing strings.It can generate random passwords and hash them using popular algorithms: `MD5`, `SHA-256`, or `SHA-512`


## 🔐 Features

- **Generate strong random passwords** 
- **Hash any password or string** 
  - MD5
  - SHA-256
  - SHA-512
- **Clean interactive menu interface**
- **Uses modern OpenSSL EVP API** 
- **Secure random generation** 


## ⚙️ Requirements

- GCC (or compatible C compiler)
- OpenSSL development libraries (libssl-dev on Debian/Ubuntu)


## 🚀 Installation & Running

  1. Clone or download this repository:
     
    git clone https://github.com/Zzorro-Kid/Password_Tool.git
     
  2. Navigate to the project directory:

    cd Password_Tool
     
  3. Compile the program:

    g++ password_tool.cpp -o password_tool -lcrypto
  
  4. Run the tool:

    ./password_tool
     


