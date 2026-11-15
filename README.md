# File-Integrity-Checker
A file integrity checker written in C that uses OpenSSL's EVP interface to generate SHA-256 cryptographic hashes and verify file integrity.

# Requirements
- C compiler
- OpenSSL's development library

# Be Advised:
If compiling on macOS or Windows, you need to specify the paths to OpenSSL include and library directory on your machine, along with the -lcrypto flag which instructs the linker to link against OpenSSL's cr$

Ex: gcc fileIntegrityChecker.c -I [path to openssl include dir] -L [path to openssl library dir] -lcrypto

If compiling on Linux, you just need to include the -lcrypto flag for the linker against OpenSSL's crypto library.

Ex: gcc fileIntegrityChecker.c -lcrypto

