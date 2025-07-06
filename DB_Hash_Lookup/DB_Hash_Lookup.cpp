// lookup.cpp — self-contained, Windows + POSIX, UTF-8-safe
// Build with: cl /std:c++17 lookup.cpp sqlite3.c /link sqlite3.lib libcrypto.lib
// or:       g++ -std=c++17 lookup.cpp -lsqlite3 -lcrypto -o lookup

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cctype>
#include <clocale>
#include <sqlite3.h>
#include <openssl/sha.h>
#include <fstream>

#ifdef _WIN32
// Convert wide UTF-16 command-line args to UTF-8
std::string utf8_from_wide(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string utf8(size_needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), &utf8[0], size_needed, nullptr, nullptr);
    return utf8;
}
#endif

// Compute SHA-256 hex digest of input
std::string sha256_hex(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) oss << std::setw(2) << (int)hash[i];
    return oss.str();
}

// Lowercase helper
std::string to_lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return std::tolower(c); });
    return out;
}

// Case-insensitive suffix check
bool ends_with_ci(const std::string& s, const std::string& suf) {
    if (s.size() < suf.size()) return false;
    return to_lower(s.substr(s.size() - suf.size())) == to_lower(suf);
}

// JSON-escape helper
std::string json_escape(const std::string& s) {
    std::ostringstream o;
    for (unsigned char c : s) {
        switch (c) {
        case '"': o << "\\\""; break;
        case '\\': o << "\\\\"; break;
        case '\b': o << "\\b"; break;
        case '\f': o << "\\f"; break;
        case '\n': o << "\\n"; break;
        case '\r': o << "\\r"; break;
        case '\t': o << "\\t"; break;
        default:
            if (c < 0x20) {
                o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
            }
            else {
                o << c;
            }
        }
    }
    return o.str();
}

// Collect rows from prepared statement
std::vector<std::map<std::string, std::string>> collect_rows(sqlite3_stmt* stmt) {
    std::vector<std::map<std::string, std::string>> rows;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::map<std::string, std::string> row;
        int cols = sqlite3_column_count(stmt);
        for (int i = 0; i < cols; ++i) {
            const char* name = sqlite3_column_name(stmt, i);
            const unsigned char* val = sqlite3_column_text(stmt, i);
            row[name] = val ? reinterpret_cast<const char*>(val) : std::string();
        }
        rows.push_back(std::move(row));
    }
    return rows;
}

// Lookup by phone (international, any country)
std::vector<std::map<std::string, std::string>> lookup_by_phone(sqlite3* db, const std::string& table, const std::string& phone) {
    // Strip non-digit characters, preserve '+' if present
    bool has_plus = false;
    std::string digits;
    for (unsigned char c : phone) {
        if (c == '+') has_plus = true;
        if (std::isdigit(c)) digits.push_back(c);
    }
    // Build variants: always try both with and without '+' prefix
    std::vector<std::string> variants;
    if (has_plus) {
        variants.push_back("+" + digits);
        variants.push_back(digits);
    }
    else {
        variants.push_back(digits);
        variants.push_back("+" + digits);
    }
    // Compute hashes for each variant
    std::vector<std::string> hashes;
    for (auto& v : variants) hashes.push_back(sha256_hex(v));

    // Get SHA columns from table
    sqlite3_stmt* cols;
    std::string pr = "PRAGMA table_info('" + table + "');";
    sqlite3_prepare_v2(db, pr.c_str(), -1, &cols, nullptr);
    std::vector<std::string> shaCols;
    while (sqlite3_step(cols) == SQLITE_ROW) {
        std::string col = reinterpret_cast<const char*>(sqlite3_column_text(cols, 1));
        if (ends_with_ci(col, "_sha") || ends_with_ci(col, "_sha256")) shaCols.push_back(col);
    }
    sqlite3_finalize(cols);
    if (shaCols.empty()) return {};

    // Build query with placeholders
    std::ostringstream ss;
    ss << "SELECT * FROM '" << table << "' WHERE ";
    for (size_t i = 0; i < shaCols.size(); ++i) {
        if (i) ss << " OR ";
        ss << '"' << shaCols[i] << '"' << " IN (";
        for (size_t j = 0; j < hashes.size(); ++j) {
            if (j) ss << ',';
            ss << '?';
        }
        ss << ')';
    }
    sqlite3_stmt* st;
    sqlite3_prepare_v2(db, ss.str().c_str(), -1, &st, nullptr);
    int idx = 1;
    for (auto& col : shaCols) for (auto& h : hashes) sqlite3_bind_text(st, idx++, h.c_str(), -1, SQLITE_TRANSIENT);
    auto rows = collect_rows(st);
    sqlite3_finalize(st);
    return rows;
}

// Lookup by address
std::vector<std::map<std::string, std::string>> lookup_by_address(sqlite3* db, const std::string& table, const std::string& q) {
    sqlite3_stmt* cols;
    std::string pr = "PRAGMA table_info('" + table + "');";
    sqlite3_prepare_v2(db, pr.c_str(), -1, &cols, nullptr);
    std::vector<std::string> addrCols;
    while (sqlite3_step(cols) == SQLITE_ROW) {
        std::string col = reinterpret_cast<const char*>(sqlite3_column_text(cols, 1));
        auto lc = to_lower(col);
        if (lc.find("addr") != std::string::npos || lc.find("street") != std::string::npos || lc.find("city") != std::string::npos)
            addrCols.push_back(col);
    }
    sqlite3_finalize(cols);
    std::vector<std::map<std::string, std::string>> result;
    for (auto& col : addrCols) {
        std::string sql = "SELECT *, '" + col + "' AS matched_col FROM '" + table + "' WHERE lower(\"" + col + "\") LIKE lower(?)";
        sqlite3_stmt* st;
        sqlite3_prepare_v2(db, sql.c_str(), -1, &st, nullptr);
        std::string pat = "%" + q + "%";
        sqlite3_bind_text(st, 1, pat.c_str(), -1, SQLITE_TRANSIENT);
        auto rows = collect_rows(st);
        sqlite3_finalize(st);
        result.insert(result.end(), rows.begin(), rows.end());
    }
    return result;
}

// Lookup by hash
static std::vector<std::map<std::string, std::string>> lookup_by_hash(
    sqlite3* db,
    const std::string& tbl,
    const std::string& raw
) {
    std::string h = sha256_hex(raw);

    // Determine JSON array column and SHA columns
    sqlite3_stmt* cols_stmt;
    sqlite3_prepare_v2(db, ("PRAGMA table_info('" + tbl + "');").c_str(), -1, &cols_stmt, nullptr);
    bool hasJson = false;
    std::vector<std::string> shaCols;
    while (sqlite3_step(cols_stmt) == SQLITE_ROW) {
        std::string colName = reinterpret_cast<const char*>(sqlite3_column_text(cols_stmt, 1));
        if (colName == "row_hashes") hasJson = true;
        if (ends_with_ci(colName, "_sha") || ends_with_ci(colName, "_sha256")) {
            shaCols.push_back(colName);
        }
    }
    sqlite3_finalize(cols_stmt);

    std::vector<std::map<std::string, std::string>> out;

    // JSON array lookup
    if (hasJson) {
        std::string jsql =
            "SELECT t.* FROM '" + tbl + "' t, json_each(t.row_hashes) je WHERE je.value = ?";
        sqlite3_stmt* js;
        sqlite3_prepare_v2(db, jsql.c_str(), -1, &js, nullptr);
        sqlite3_bind_text(js, 1, h.c_str(), -1, SQLITE_TRANSIENT);
        auto jrows = collect_rows(js);
        sqlite3_finalize(js);
        out.insert(out.end(), jrows.begin(), jrows.end());
    }

    // Direct SHA column lookup
    if (!shaCols.empty()) {
        std::ostringstream qss;
        qss << "SELECT * FROM '" << tbl << "' WHERE ";
        for (size_t i = 0; i < shaCols.size(); ++i) {
            if (i) qss << " OR ";
            qss << '"' << shaCols[i] << '"' << " = ?";
        }
        sqlite3_stmt* ss;
        sqlite3_prepare_v2(db, qss.str().c_str(), -1, &ss, nullptr);
        for (size_t i = 0; i < shaCols.size(); ++i) {
            sqlite3_bind_text(ss, static_cast<int>(i + 1), h.c_str(), -1, SQLITE_TRANSIENT);
        }
        auto srows = collect_rows(ss);
        sqlite3_finalize(ss);
        out.insert(out.end(), srows.begin(), srows.end());
    }

    return out;
}

// JSON writing — Windows
#ifdef _WIN32
bool write_json_windows(const std::wstring& wpath, const std::vector<std::map<std::string, std::string>>& rows) {
    std::string pathUtf8 = utf8_from_wide(wpath);
    FILE* f = nullptr;
    if (_wfopen_s(&f, wpath.c_str(), L"wb, ccs=UTF-8") || !f) {
        std::cerr << "Cannot open " << pathUtf8 << "\n";
        return false;
    }
    fputc('[', f);
    for (size_t i = 0; i < rows.size(); ++i) {
        fputc('{', f);
        bool first = true;
        for (auto& kv : rows[i]) {
            if (!first) fputc(',', f);
            std::string ent = "\"" + json_escape(kv.first) + "\":\"" + json_escape(kv.second) + "\"";
            fwrite(ent.c_str(), 1, ent.size(), f);
            first = false;
        }
        fputc('}', f);
        if (i + 1 < rows.size()) fputc(',', f);
    }
    fputc(']', f);
    fclose(f);
    std::cout << "Wrote " << pathUtf8 << "\n";
    return true;
}
#endif

// JSON writing — POSIX
bool write_json_posix(const std::string& path, const std::vector<std::map<std::string, std::string>>& rows) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) { std::cerr << "Cannot open " << path << "\n"; return false; }
    ofs << '[';
    for (size_t i = 0; i < rows.size(); ++i) {
        ofs << '{';
        bool first = true;
        for (auto& kv : rows[i]) {
            if (!first) ofs << ',';
            ofs << '"' << json_escape(kv.first) << "\":\"" << json_escape(kv.second) << '"';
            first = false;
        }
        ofs << '}';
        if (i + 1 < rows.size()) ofs << ',';
    }
    ofs << ']';
    ofs.close();
    std::cout << "Wrote " << path << "\n";
    return true;
}

// main logic
int run(int argc, char** argv) {
    std::setlocale(LC_ALL, "");
    if (argc < 5) { std::cerr << "Usage:<exe> <db> <table> <mode> [--json] <query>\n"; return 1; }
    int i = 1;
    const char* dbFile = argv[i++];
    std::string table = argv[i++];
    std::string mode = argv[i++];
    bool jsonOut = false;
    if (std::string(argv[i]) == "--json") { jsonOut = true; i++; }
    std::string query = argv[i];

    sqlite3* db;
    if (sqlite3_open(dbFile, &db) != SQLITE_OK) { std::cerr << sqlite3_errmsg(db) << "\n"; return 1; }
    std::vector<std::map<std::string, std::string>> rows;
    if (mode == "phone") rows = lookup_by_phone(db, table, query);
    else if (mode == "address") rows = lookup_by_address(db, table, query);
    else if (mode == "hash") rows = lookup_by_hash(db, table, query);
    else { std::cerr << "Unknown mode\n"; sqlite3_close(db); return 1; }
    sqlite3_close(db);

    if (jsonOut) {
#ifdef _WIN32
        CreateDirectoryW(L"static", nullptr);
        int wlen = MultiByteToWideChar(CP_UTF8, 0, query.c_str(), -1, nullptr, 0);
        std::wstring wq(wlen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, query.c_str(), -1, &wq[0], wlen);
        // sanitize
        std::wstring safe;
        for (wchar_t c : wq) safe += (iswalnum(c) || c == L' ' || c == L'_') ? c : L'_';
        std::wstring wpath = L"static\\" + safe + L".json";
        write_json_windows(wpath, rows);
#else
        mkdir("static", 0755);
        std::string safe;
        for (unsigned char c : query) safe += isalnum(c) ? c : '_';
        std::string path = "static/" + safe + ".json";
        write_json_posix(path, rows);
#endif
    }
    else {
        for (auto& r : rows) {
            std::cout << "---- Row ----\n";
            for (auto& kv : r) std::cout << kv.first << ": " << kv.second << "\n";
        }
    }
    return 0;
}

#ifdef _WIN32
int wmain(int argc, wchar_t** wargv) {
    std::vector<std::string> args;
    for (int j = 0; j < argc; ++j) args.push_back(utf8_from_wide(wargv[j]));
    std::vector<char*> cargs;
    for (auto& s : args) cargs.push_back(const_cast<char*>(s.c_str()));
    return run(argc, cargs.data());
}
#else
int main(int argc, char** argv) { return run(argc, argv); }
#endif
