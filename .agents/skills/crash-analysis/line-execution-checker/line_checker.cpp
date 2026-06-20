// line_checker.cpp - Check if specific lines were executed
// Compile: g++ -O3 -std=c++17 line_checker.cpp -o line-checker
// Usage: ./line-checker file.c:line [file.c:line ...]

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <filesystem>

namespace fs = std::filesystem;

struct Query {
    std::string file;
    int line;
};

// Parse .gcov file to extract execution counts
std::unordered_map<int, uint64_t> parse_gcov_file(const std::string& filename) {
    std::unordered_map<int, uint64_t> line_counts;
    std::ifstream file(filename);
    if (!file.is_open()) return line_counts;
    
    std::string line;
    while (std::getline(file, line)) {
        // Format: "count:line_num:source"
        // Skip header lines
        if (line.find(":    0:") != std::string::npos) continue;
        
        std::istringstream iss(line);
        std::string count_str;
        int line_num;
        char c1, c2;
        
        iss >> count_str >> c1 >> line_num >> c2;
        if (c1 != ':' || c2 != ':') continue;
        
        // Parse count: "#####" = 0, "-" = non-executable, else number
        uint64_t count = 0;
        if (count_str.find("#####") != std::string::npos) {
            count = 0;
        } else if (count_str.find("-") != std::string::npos) {
            continue; // Non-executable
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
    std::string cmd = "gcov " + source_file + " >/dev/null 2>&1";
    system(cmd.c_str());
    
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
    q.line = std::stoi(arg.substr(colon + 1));
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
