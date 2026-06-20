// trace_to_perfetto.cpp - Convert trace logs to Perfetto Chrome JSON
// Compile: g++ -O3 -std=c++17 trace_to_perfetto.cpp -o trace_to_perfetto
// Usage: ./trace_to_perfetto trace_*.log -o output.json

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <regex>
#include <algorithm>
#include <cstring>

struct Event {
    std::string function;
    char phase;  // 'B' or 'E'
    uint64_t timestamp_us;
    int pid;
    int tid;
};

int extract_tid(const std::string& filename) {
    std::regex tid_regex(R"(trace_(\d+)\.log)");
    std::smatch match;
    if (std::regex_search(filename, match, tid_regex)) {
        return std::stoi(match[1].str());
    }
    return -1;
}

bool parse_line(const std::string& line, uint64_t& seq, double& ts, int& depth, 
                char& phase, std::string& func) {
    if (line.empty() || line[0] == '#') return false;
    
    const char* ptr = line.c_str();
    if (*ptr != '[') return false;
    ptr++;
    
    // Parse sequence
    seq = 0;
    while (*ptr >= '0' && *ptr <= '9') {
        seq = seq * 10 + (*ptr - '0');
        ptr++;
    }
    if (*ptr != ']') return false;
    ptr++;
    
    // Skip to timestamp
    while (*ptr == ' ') ptr++;
    if (*ptr != '[') return false;
    ptr++;
    
    // Parse timestamp
    ts = 0.0;
    uint64_t int_part = 0;
    while (*ptr >= '0' && *ptr <= '9') {
        int_part = int_part * 10 + (*ptr - '0');
        ptr++;
    }
    ts = static_cast<double>(int_part);
    
    if (*ptr == '.') {
        ptr++;
        double frac = 0.0;
        double divisor = 10.0;
        while (*ptr >= '0' && *ptr <= '9') {
            frac += (*ptr - '0') / divisor;
            divisor *= 10.0;
            ptr++;
        }
        ts += frac;
    }
    
    if (*ptr != ']') return false;
    ptr++;
    while (*ptr == ' ') ptr++;
    
    // Count dots
    depth = 0;
    while (*ptr == '.') {
        depth++;
        ptr++;
    }
    while (*ptr == ' ') ptr++;
    
    // Parse event type
    if (*ptr != '[') return false;
    ptr++;
    
    if (strncmp(ptr, "ENTRY", 5) == 0) {
        phase = 'B';
        ptr += 5;
    } else if (strncmp(ptr, "EXIT!", 5) == 0) {
        phase = 'E';
        ptr += 5;
    } else {
        return false;
    }
    
    if (*ptr != ']') return false;
    ptr++;
    while (*ptr == ' ') ptr++;
    
    // Rest is function name
    func = ptr;
    while (!func.empty() && (func.back() == ' ' || func.back() == '\n' || func.back() == '\r')) {
        func.pop_back();
    }
    
    return !func.empty();
}

std::string escape_json(const std::string& str) {
    std::string result;
    for (char c : str) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result += c;
        }
    }
    return result;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <trace_files...> -o <output.json>\n";
        return 1;
    }
    
    std::vector<std::string> input_files;
    std::string output_file;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else {
            input_files.push_back(argv[i]);
        }
    }
    
    if (output_file.empty() || input_files.empty()) {
        std::cerr << "Error: Must specify input files and -o output.json\n";
        return 1;
    }
    
    std::vector<Event> events;
    
    // Load all trace files
    for (const auto& filename : input_files) {
        int tid = extract_tid(filename);
        if (tid < 0) continue;
        
        std::ifstream file(filename);
        if (!file.is_open()) continue;
        
        std::string line;
        while (std::getline(file, line)) {
            uint64_t seq;
            double timestamp;
            int depth;
            char phase;
            std::string function;
            
            if (!parse_line(line, seq, timestamp, depth, phase, function)) {
                continue;
            }
            
            Event e;
            e.function = function;
            e.phase = phase;
            e.timestamp_us = static_cast<uint64_t>(timestamp * 1000000.0);
            e.pid = tid;
            e.tid = tid;
            
            events.push_back(e);
        }
    }
    
    // Sort by timestamp
    std::sort(events.begin(), events.end(), 
              [](const Event& a, const Event& b) { return a.timestamp_us < b.timestamp_us; });
    
    // Write JSON
    std::ofstream out(output_file);
    if (!out.is_open()) {
        std::cerr << "Error: Cannot open " << output_file << "\n";
        return 1;
    }
    
    out << "{\n  \"traceEvents\": [\n";
    
    // Write events
    for (size_t i = 0; i < events.size(); i++) {
        const auto& e = events[i];
        if (i > 0) out << ",\n";
        
        out << "    {\"name\":\"" << escape_json(e.function) << "\","
            << "\"cat\":\"function\","
            << "\"ph\":\"" << e.phase << "\","
            << "\"ts\":" << e.timestamp_us << ","
            << "\"pid\":" << e.pid << ","
            << "\"tid\":" << e.tid << "}";
    }
    
    out << "\n  ],\n";
    out << "  \"displayTimeUnit\": \"ns\"\n";
    out << "}\n";
    
    std::cerr << "Converted " << events.size() << " events to " << output_file << "\n";
    std::cerr << "Open in Perfetto: https://ui.perfetto.dev\n";
    
    return 0;
}
