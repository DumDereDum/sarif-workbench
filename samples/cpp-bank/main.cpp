/*
 * VULNERABLE BANK APP — intentionally insecure, for semgrep benchmarking.
 * DO NOT USE IN PRODUCTION.
 *
 * Vulnerabilities planted:
 *   CWE-121  Stack buffer overflow via gets()
 *   CWE-676  Use of dangerous function strcpy / sprintf without bounds
 *   CWE-134  Uncontrolled format string
 *   CWE-89   SQL injection (simulated query building)
 *   CWE-78   OS command injection via system()
 *   CWE-798  Hard-coded credentials
 *   CWE-190  Integer overflow in balance arithmetic
 *   CWE-476  NULL pointer dereference after malloc
 *   CWE-401  Memory leak (malloc without free)
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

// CWE-798: hard-coded credentials
static const char* ADMIN_PASSWORD = "admin123";
static const char* DB_CONNECTION  = "host=prod-db user=root password=SuperSecret99";

struct Account {
    int    id;
    char   owner[64];
    double balance;
};

// ── auth ──────────────────────────────────────────────────────────────────────

bool authenticate(const char* username, const char* password) {
    char buf[32];
    // CWE-676 / CWE-121: strcpy into fixed-size buffer, no bounds check
    strcpy(buf, username);

    // CWE-798: compare against literal secret
    if (strcmp(password, ADMIN_PASSWORD) == 0) {
        return true;
    }

    // CWE-89: SQL injection — user input concatenated directly into query string
    char query[256];
    sprintf(query,
            "SELECT * FROM users WHERE name='%s' AND pass='%s'",
            username, password);
    printf("[DB] %s\n", query);

    return false;
}

// ── account ops ───────────────────────────────────────────────────────────────

Account* create_account(int id, const char* owner_name) {
    // CWE-401: malloc result used, but never freed in error path
    Account* acc = (Account*)malloc(sizeof(Account));

    // CWE-476: malloc result not checked before use
    acc->id      = id;
    acc->balance = 0.0;

    // CWE-676: strcpy without bounds check into acc->owner[64]
    strcpy(acc->owner, owner_name);

    return acc;
}

void deposit(Account* acc, int amount) {
    // CWE-190: signed integer overflow — no check before addition
    acc->balance += amount;
    printf("Deposited %d. New balance: %.2f\n", amount, acc->balance);
}

void print_account(Account* acc) {
    char msg[128];
    // CWE-676: sprintf into fixed buffer without length check
    sprintf(msg, "Account #%d | Owner: %s | Balance: %.2f",
            acc->id, acc->owner, acc->balance);
    puts(msg);
}

// ── reporting ─────────────────────────────────────────────────────────────────

void export_report(const char* filename) {
    char cmd[256];
    // CWE-78: OS command injection — filename comes from user, passed to system()
    sprintf(cmd, "cat /var/bank/reports/%s", filename);
    system(cmd);
}

void log_event(const char* user_message) {
    // CWE-134: uncontrolled format string — user_message used as format directly
    printf(user_message);
}

// ── input ─────────────────────────────────────────────────────────────────────

void read_username(char* out) {
    printf("Username: ");
    // CWE-121: gets() — classic unbounded stack buffer overflow
    gets(out);
}

// ── main ──────────────────────────────────────────────────────────────────────

int main() {
    char username[64];
    char password[64];
    char report_name[128];

    printf("=== Vulnerable Bank v1.0 ===\n");
    printf("DB: %s\n", DB_CONNECTION);   // leaks credentials to stdout

    read_username(username);

    printf("Password: ");
    gets(password);  // CWE-121: second gets() call

    if (!authenticate(username, password)) {
        printf("Access denied.\n");
        return 1;
    }

    Account* acc = create_account(1001, username);
    deposit(acc, 500);
    print_account(acc);

    printf("Report file to view: ");
    gets(report_name);   // CWE-121: third gets() call, fed into system()
    export_report(report_name);

    log_event(username); // CWE-134: username as format string

    // CWE-401: acc is never freed
    return 0;
}
