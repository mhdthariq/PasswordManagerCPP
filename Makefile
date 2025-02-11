# Detect OS
UNAME := $(shell uname)

# Default compiler (GCC or Clang)
CXX := g++
ALTERNATE_CXX := clang++

# Check if Clang is available, fallback to GCC if not
ifeq ($(shell which clang++ 2>/dev/null),)
    CXX := g++
else
    CXX := clang++
endif

# Compiler flags
CXXFLAGS := -std=c++17 -Wall -Wextra

# Libraries
LIBS := -lssl -lcrypto

# Output binary
TARGET := PasswordManager

# Source files
SRC := PasswordManager.cpp

# OS-specific settings
ifeq ($(UNAME), Linux)
    CXXFLAGS += -O2
else ifeq ($(UNAME), Darwin)
    # macOS settings (Homebrew OpenSSL)
    OPENSSL_PATH := /usr/local/opt/openssl
    CXXFLAGS += -I$(OPENSSL_PATH)/include -L$(OPENSSL_PATH)/lib
else ifeq ($(OS), Windows_NT)
    # Windows (MSYS2)
    TARGET := PasswordManager.exe
endif

# Default target
all: $(TARGET)

# Build the executable
$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

# Clean build files
clean:
	rm -f $(TARGET)

