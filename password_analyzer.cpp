#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <ios>
#include <iostream>
#include <string>
#include <unordered_set>
#include <fstream>
#include <vector>
#include <cmath>
#include <iomanip>


static inline bool is_symbol(char c){
    return !(isalnum(static_cast<unsigned char>(c)));
}

double log2_double(double x) {
    return log(x) / log(2.0);
}

double pool_based_entropy_bits(const std::string &str){
    bool lower = false, upper = false, digit = false, symbol = false;

    int symbol_count = 0;
    for(unsigned char c : str){
        if(islower(c)) {
            lower = true;
        }
        else if(std::isupper(c)) {
            upper = true;
        }
        else if(isdigit(c)){
            digit = true;
        }
        else {
            symbol = true;
            ++symbol_count;
        }
    }

    int pool = 0;
    if(lower){
        pool += 26;
    }
    if(upper){
        pool += 26;
    }
    if(digit){
        pool += 10;
    }
    if(symbol){
        pool += 32;
    }

    if(pool <= 0) {
        pool = 1;
    }

    double bits_per_char = log2_double(pool);

    return bits_per_char * str.size();
}

double shannon_entropy(const std::string &str){
    if(str.empty()) {
        return 0.0;
    }

    std::array<int, 256> freq{};
    freq.fill(0);

    for(unsigned char c : str){
        freq[c]++;
    }

    double H = 0.0;
    for(int f : freq){
        if(f > 0){
            double p = (double)f / str.size();
            H -= p * log2_double(p);
        }
    }
    return H * str.size();
}

bool has_sequence(const std::string &s, int seqLen = 4){
    if((int)s.size() < seqLen){
        return false;
    }

    for(std::size_t i = 0; i + seqLen <= s.size(); ++i){
        bool inc = true, dec = true;

        for(int j = 1; j < seqLen; ++j){
            if((unsigned char)s[i + j] != (unsigned char)(s[i + j - 1] + 1)){
                inc = false;
            }

            if((unsigned char)s[i + j] != (unsigned char)(s[i + j - 1] - 1)) {
                dec = false;
            } 
        }
        if(inc || dec) {
            return true;
        }
    }
    return false;
}

bool has_repeated_chars(const std::string &str, int runLen = 4){
    if((int)str.size() < runLen) {
        return false;
    }

    for(std::size_t i = 0; i + runLen <= str.size(); ++i){
        bool same = true;
        for(int j = 1; j < runLen; ++j){
            if(str[i + j] != str[i + j - 1]){
                same = false;
                break;
            }
        }
        if(same) {
            return true;
        }
    }
    return false;
}

bool contains_case_insensitive(const std::string &str, const std::string &sub){
    auto tolow = [&](const std::string &x) {
        std::string r = x;
        for(auto &c : r){
            c = tolower(c);
        }
        return r;
    };
    std::string a = tolow(str), b = tolow(sub);
    return a.find(b) != std::string::npos;
}

struct AnalysisResult {
    int score; // from 0 to 100
    double entropy_bits;
    double shannon_bits;
    std::vector<std::string> reasons;
};

AnalysisResult analyze_password(const std::string &pw, const std::unordered_set<std::string> &commonPasswords) {
    AnalysisResult result{};

    if(pw.empty()){
        result.score = 0;
        result.entropy_bits = 0;
        result.shannon_bits = 0;
        result.reasons.push_back(" Empty password");
        return result;
    }

    double pool_bits = pool_based_entropy_bits(pw);
    double shannon = shannon_entropy(pw);
    result.entropy_bits = pool_bits;
    result.shannon_bits = shannon;

    std::string pw_lower = pw;
    for(auto &c : pw_lower){
        c = tolower(c);
    }

    if(!commonPasswords.empty() && commonPasswords.find(pw_lower) != commonPasswords.end()){
        result.score = 5;
        result.reasons.push_back(" Password is in common-password list");
        return result;
    }


    double bits = pool_bits;
    double base = 0.0;

    base = std::min(80.0, (bits / 60.0) * 80.0);

    double length_bonus = std::min(15.0, (pw.size() > 8) ? (pw.size() - 8) * 1.5 : 0.0);
    double score = base + length_bonus;
    
    if(score > 95.0) {
        score = 95.0;
    }

    // Penalties
    if(has_sequence(pw, 4)){
        score -= 15;
        result.reasons.push_back(" Contains increasing/decreasing sequence (e.g. 'abcd' or '1234')");
    }

    if(has_repeated_chars(pw, 4)){
        score -= 15;
        result.reasons.push_back(" Contains long repeated characters (e.g 'aaaaa')");
    }

    //checking common substrings
    std::vector<std::string> commonSubs = {"password", "qwerty", "admin", "welcome", "12345", "iloveyou", "123456789"};

    for(auto &sub : commonSubs){
        if(contains_case_insensitive(pw, sub)){
            score -= 20;
            result.reasons.push_back(" Contains a common substring: '" + sub + "'");
            break;
        }
    }

    //too short
    if(pw.size() < 8){
        score -= (int)((8 - pw.size()) * 6);
        result.reasons.push_back(" Short password (less than 8 characters)"); 
    }
    else if(pw.size() < 12){
        result.reasons.push_back(" Consider using a longer passphrase (12+ characters recommended)");
    }

    //weak
    bool lower = false, upper = false, digit = false, sym = false;
    for(unsigned char c : pw){
        if(std::islower(c)){
            lower = true;
        }
        else if(isupper(c)){
            upper = true;
        }
        else if(isdigit(c)){
            digit = true;
        }
        else {
            sym = true;
        }
    }

    int classes = (int)lower + (int)upper + (int)digit + (int)sym;
    if(classes <= 1){
        score -= 25;
        result.reasons.push_back(" Uses only character class (add uppercase, digits, or symbols)");
    }

    if(score < 0){
        score = 0;
    }
    if(score > 100){
        score = 100;
    }

    result.score = (int) std::round(score);

    if(result.reasons.empty()){
        result.reasons.push_back(" No obvious weaknesses detected");
    }

    return result;
}


std::unordered_set<std::string> load_common_passwords(const std::string &filename) {
    std::unordered_set<std::string> str;

    if(filename.empty()) {
        return str;
    }

    std::ifstream in(filename);
    if(!in){
        std::cerr << "Warning: could not open common-passwords file: " << filename << "\n";
        return str;
    }
    std::string line;
    while(std::getline(in, line)){
        while(!line.empty() && std::isspace((unsigned char) line.back())) {
            line.pop_back();
        }
        
        std::size_t start = 0;
        while(start < line.size() && std::isspace((unsigned char) line[start])){
            ++start;
        }

        std::string p = (start ? line.substr(start) : line);
        for(auto &c : p){
            c = tolower(c);
        }

        if(!p.empty()){
            str.insert(p);
        }
    }
    return str;
}

int main(int argc, char **argv){
  std::ios::sync_with_stdio(false);
  std::cin.tie(nullptr);

  std::string common_file = (argc >= 2) ? argv[1] : "";
  auto common = load_common_passwords(common_file);

  std::cout << "Password Strength Analyzer (C++)\n";
  std::cout << "Type a password and press Enter (Ctrl + D to exit): \n\n";

  std::string pw;

  while(true){
    std::cout << "Password: ";
    
    if(!getline(std::cin, pw)){
        break;
    }

    if(!pw.empty() && pw.back() == '\r'){
        pw.pop_back();
    }

    AnalysisResult r = analyze_password(pw, common);
    std::cout << "\nScore: " << r.score << " / 100\n";
    std::cout << "Estimated entropy (pool-based): " << std::fixed << std::setprecision(2) << r.entropy_bits << " bits\n";
    std::cout << "Estimated entropy (Shannon): " << std::fixed << std::setprecision(2) << r.shannon_bits << " bits\n";
    std::cout << "Feedback:\n";
    for(auto &msg : r.reasons) {
        std::cout << " - " << msg << "\n";
    }

    if(r.score < 40) {
        std::cout << "Recommendation: Use a longer passphrase (at least 12 characters), mix character types, and avoid common words. \n";
    }
    std::cout << std::endl;
  }

  std::cout << "\nGoodbye!!!\n";

  return 0;
}