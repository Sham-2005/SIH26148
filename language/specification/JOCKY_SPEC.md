# JOCKY Language Specification (v1.0.0-MVP)

## 1. Syntax Overview
JOCKY is a declarative, safe domain-specific language for digital-forensics and incident-response operations.

## 2. EBNF Grammar

```ebnf
program             ::= script_declaration*
script_declaration  ::= "script" IDENTIFIER "{" statement* "}"

statement           ::= variable_decl
                      | assignment
                      | function_call ";"
                      | if_statement
                      | for_statement

variable_decl       ::= IDENTIFIER "=" expression ";"
assignment          ::= IDENTIFIER "=" expression ";"

function_call       ::= IDENTIFIER "." IDENTIFIER "(" argument_list? ")"
argument_list       ::= expression ("," expression)*

expression          ::= literal
                      | IDENTIFIER
                      | function_call

literal             ::= STRING
                      | NUMBER
                      | BOOLEAN

if_statement        ::= "if" expression "{" statement* "}" ("else" "{" statement* "}")?
for_statement       ::= "for" IDENTIFIER "in" expression "{" statement* "}"

IDENTIFIER          ::= [a-zA-Z_][a-zA-Z0-9_]*
STRING              ::= "\"" [^"\\]* "\""
NUMBER              ::= [0-9]+ ("." [0-9]+)?
BOOLEAN             ::= "true" | "false"
COMMENT             ::= "//" [^\n]*
```

## 3. Allowed Standard Library Namespaces & Signatures

| Namespace | Function | Arguments | Description |
|---|---|---|---|
| `system` | `info()` | none | OS version, architecture, CPU, uptime, memory |
| `system` | `hostname()` | none | Endpoint hostname & FQDN |
| `system` | `os()` | none | Operating system family and release |
| `system` | `users()` | none | Enumeration of local user accounts |
| `process` | `list()` | none | Running processes (PID, Name, User, Memory, Path) |
| `process` | `info(pid)` | `pid: int` | Detailed inspection of target process |
| `process` | `modules(pid)` | `pid: int` | Loaded DLLs / shared objects in target process |
| `file` | `hash(path)` | `path: str` | MD5, SHA-1, SHA-256 calculation |
| `file` | `metadata(path)` | `path: str` | Timestamps (MACB), file size, permissions |
| `file` | `strings(path)` | `path: str` | ASCII & Unicode string extraction |
| `file` | `entropy(path)` | `path: str` | Shannon entropy calculation (0.0 - 8.0) |
| `filesystem` | `scan(path)` | `path: str` | Directory enumeration |
| `network` | `connections()` | none | Active TCP/UDP connections and listening sockets |
| `network` | `interfaces()` | none | Network adapters, MAC addresses, IP bindings |
| `network` | `dns()` | none | Configured DNS servers and resolver caches |
| `persistence`| `startup()` | none | Auto-start folders and registry run keys |
| `persistence`| `scheduled_tasks()`| none | Scheduled jobs / cron / systemd timers |
| `persistence`| `services()` | none | Installed system services and daemon status |
| `malware` | `hash(path)` | `path: str` | Malware indicator hash analysis |
| `malware` | `entropy(path)`| `path: str` | Shannon entropy analysis for packed payloads |
| `malware` | `strings(path)`| `path: str` | Extracted suspicious indicators |
| `malware` | `pe_info(path)`| `path: str` | PE/ELF headers, sections, and import table inspection |
| `evidence` | `collect()` | none | Explicit envelope seal & flush directive |
