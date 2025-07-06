# 🔍 C++ Hash-Based Database Lookup Tool

A simple and efficient C++ utility to search SQL/SQLite databases using SHA-256 hashes for phones, addresses, full names, usernames and other sensitive fields. Supports JSON output for easy integration.


# ⚙️ Features
- Lookup by phone, address, or generic hash (full name, email, username, password, etc.)

- Supports SQLite and SQL databases

- Console output or JSON file generation

- Hashes must be stored in columns with _sha256 or _sha suffixes

- Compatible with hash generation using the included addhash.py


# 🚀 Usage
`<executable_dir> <database_dir> <table_name> <mode> [--json] <query>`


Examples:

  `DB_Lookup.exe "C:/Databases/Users.db" "Google" "hash" --json "alas-m"`
  
  `DB_Lookup.exe "C:/Databases/Users.db" "Google" "hash" "alas-m"`

This will:

  ✅ Search Google in Users.db for matching _sha256 or _sha
  
  ✅ 1 - Output results to a .json file. 2 - Doesnt


# 👀 Arguments
| Argument          | Description                                                                                                                                                          |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `<executable_dir>`    | Path to the compiled C++ executable                                                                                                                                  |
| `<database_dir>` | Path to your SQLite or SQL database file                                                                                                                             |
| `<table_name>`    | The table within the database to search                                                                                                                              |
| `<mode>`          | Search mode: `phone`, `address`, or `hash`                                                                                                                           |
| `[--json]`        | *(Optional)* Add to generate `.json` file instead of console output                                                                                                  |
| `<query>`         | Search query:<br> - Phone: `+79999999999`<br> - Full Name: `"Surname Name Fathername"`<br> - Address: `"Street Address"`<br> - Username/Password/Email for hash mode |

# 🔑 Modes Explained
phone mode:
Searches columns phone_sha256 or phone_sha

Use for phone numbers (e.g., +79999999999, +12897849696)

address mode:
Searches columns address_sha256 or address_sha

Use for address lookups

hash mode:
Searches all other _sha256 or _sha columns

Can be used for full names, emails, usernames, passwords, etc.

`Note: Your database must contain hash columns named according to this structure. Use the provided addhash.py script to generate SHA-1 or SHA-256 hashes for your data.`

# ⚡ Requirements
C++17 or newer

SQLite3 (for SQLite databases)

Python 3 (for addhash.py)

# 📄 License
[MIT License]([url](https://github.com/alas-m/DatabaseLookup/tree/main?tab=MIT-1-ov-file))

# 🤝 Contributions
Feel free to fork and improve! Pull requests are welcome.
