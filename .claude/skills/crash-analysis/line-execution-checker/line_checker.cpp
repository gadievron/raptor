// line_checker.cpp - Check if specific lines were executed
// Compile: g++ -O3 -std=c++17 line_checker.cpp -o line-checker
// Usage: ./line-checker file.c:line [file.c:line ...]

#include <cctype>
#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <filesystem>

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

namespace fs = std::filesystem;

struct Query {
    std::string file;
    int line;
};

// Parse .gcov file to extract execution counts.
//
// Real gcov lines are printed as "%9s:%5d:%s" — the count and line
// number are whitespace-padded with the colon attached to the field
// ("        1:    3:puts(...)"), so whitespace-token extraction never
// sees a bare ':' token. Split on the first two colons instead.
std::unordered_map<int, uint64_t> parse_gcov_file(const std::string& filename) {
    std::unordered_map<int, uint64_t> line_counts;
    std::ifstream file(filename);
    if (!file.is_open()) return line_counts;

    std::string line;
    while (std::getline(file, line)) {
        // Format: "     count:  line_num:source"
        size_t colon1 = line.find(':');
        if (colon1 == std::string::npos) continue;
        size_t colon2 = line.find(':', colon1 + 1);
        if (colon2 == std::string::npos) continue;

        std::string count_str = line.substr(0, colon1);
        std::string line_str = line.substr(colon1 + 1, colon2 - colon1 - 1);

        // Strip the leading padding.
        count_str.erase(0, count_str.find_first_not_of(" \t"));
        line_str.erase(0, line_str.find_first_not_of(" \t"));
        if (count_str.empty() || line_str.empty()) continue;

        int line_num;
        try {
            line_num = std::stoi(line_str);
        } catch (...) {
            continue;
        }
        // Line 0 carries file-level metadata (Source:, Graph:, Runs:).
        if (line_num <= 0) continue;

        // Count field: "-" = non-executable, "#####" (and "=====" for
        // exceptional-only paths) = executable but never executed,
        // otherwise a number — possibly suffixed ("12*" marks partial
        // coverage; stoull stops at the '*').
        uint64_t count = 0;
        if (count_str == "-") {
            continue; // Non-executable
        } else if (count_str.find("#####") != std::string::npos ||
                   count_str.find("=====") != std::string::npos) {
            count = 0;
        } else {
            try {
                count = std::stoull(count_str);
            } catch (...) {
                continue;
            }
        }

        line_counts[line_num] = count;
    }

    return line_counts;
}

// Source names arrive on argv from file:line queries the
// crash-analysis flow derives from bug-tracker reports —
// attacker-shaped, so they must never reach a shell and must not be
// option-shaped when passed to gcov.
bool valid_source_name(const std::string& s) {
    if (s.empty() || s[0] == '-') return false;
    for (char ch : s) {
        if (!(std::isalnum(static_cast<unsigned char>(ch)) ||
              ch == '.' || ch == '_' || ch == '/' || ch == '-' ||
              ch == '+')) {
            return false;
        }
    }
    return true;
}

// Run "gcov <source_file>" with an argv array (no shell), output
// discarded. Failure is tolerated: the caller re-scans for .gcov
// files and reports "no coverage data" if none appeared.
void run_gcov(const std::string& source_file) {
    if (!valid_source_name(source_file)) return;
    pid_t pid = fork();
    if (pid == 0) {
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }
        execlp("gcov", "gcov", source_file.c_str(),
               static_cast<char*>(nullptr));
        _exit(127);
    } else if (pid > 0) {
        int status = 0;
        waitpid(pid, &status, 0);
    }
}

// Find .gcov file for source file
std::string find_gcov_file(const std::string& source_file) {
    std::string basename = fs::path(source_file).filename().string();
    
    // Look for matching .gcov file
    try {
        for (const auto& entry : fs::recursive_directory_iterator(".")) {
            if (entry.path().extension() == ".gcov") {
                std::string gcov_name = entry.path().filename().string();
                if (gcov_name.find(basename) == 0) {
                    return entry.path().string();
                }
            }
        }
    } catch (...) {}
    
    // Try to generate if not found
    run_gcov(source_file);
    
    // Look again
    try {
        for (const auto& entry : fs::directory_iterator(".")) {
            if (entry.path().extension() == ".gcov") {
                std::string gcov_name = entry.path().filename().string();
                if (gcov_name.find(basename) == 0) {
                    return entry.path().string();
                }
            }
        }
    } catch (...) {}
    
    return "";
}

// Parse query: "file.c:42"
Query parse_query(const std::string& arg) {
    size_t colon = arg.find(':');
    if (colon == std::string::npos) {
        std::cerr << "Invalid format: " << arg << " (use file:line)" << std::endl;
        exit(2);
    }
    
    Query q;
    q.file = arg.substr(0, colon);
    try {
        q.line = std::stoi(arg.substr(colon + 1));
    } catch (const std::exception&) {
        // Non-numeric or out-of-range line part: take the usage
        // path, not an uncaught-exception terminate.
        std::cerr << "Invalid line number: " << arg
                  << " (use file:line)" << std::endl;
        exit(2);
    }
    return q;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <file:line> [<file:line> ...]" << std::endl;
        std::cerr << "Example: " << argv[0] << " main.c:42 util.c:100" << std::endl;
        return 2;
    }
    
    // Parse queries
    std::vector<Query> queries;
    for (int i = 1; i < argc; i++) {
        queries.push_back(parse_query(argv[i]));
    }
    
    // Cache for parsed .gcov files
    std::unordered_map<std::string, std::unordered_map<int, uint64_t>> cache;
    
    bool all_executed = true;
    
    // Process each query
    for (const auto& q : queries) {
        // Get coverage data for file
        if (cache.find(q.file) == cache.end()) {
            std::string gcov_file = find_gcov_file(q.file);
            if (gcov_file.empty()) {
                std::cerr << "Error: No coverage data for " << q.file << std::endl;
                return 2;
            }
            cache[q.file] = parse_gcov_file(gcov_file);
        }
        
        auto& line_counts = cache[q.file];
        
        // Check if line was executed
        std::cout << q.file << ":" << q.line << " ";
        
        if (line_counts.find(q.line) != line_counts.end()) {
            uint64_t count = line_counts[q.line];
            if (count > 0) {
                std::cout << "EXECUTED (" << count << " time";
                if (count != 1) std::cout << "s";
                std::cout << ")" << std::endl;
            } else {
                std::cout << "NOT EXECUTED" << std::endl;
                all_executed = false;
            }
        } else {
            std::cout << "NOT EXECUTED" << std::endl;
            all_executed = false;
        }
    }
    
    return all_executed ? 0 : 1;
}
