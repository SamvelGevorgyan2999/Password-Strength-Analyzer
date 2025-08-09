# Password Strength Analyzer (C++)

A simple command-line password strength analyzer demonstrating low-level C++ string handling,
entropy estimation, and defensive checks (dictionary, sequences, repetitions).

## Features
- Estimates entropy (pool-based and Shannon)
- Detects sequences and repeated characters
- Optional common-password list check
- Clear feedback and recommendations

## Build
g++ -std=c++17 -O2 -o password_analyzer password_analyzer.cpp

## Usage
./password_analyzer [common_passwords.txt]
