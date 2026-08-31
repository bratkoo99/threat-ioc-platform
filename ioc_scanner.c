#define _GNU_SOURCE
#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <ctype.h>
#include <time.h>
#include <strings.h>

#define MAX_PATH 4096
#define MAX_HASHES 4096
#define MAX_PATTERNS 256
#define MAX_LINE 1024
#define BLOCK_SIZE 8192
#define MAX_WHITELIST 128

/* ========================== DATA STRUCTURES ========================== */

typedef struct {
    char hash[65];
    char family[128];
    char description[256];
} HashEntry;

typedef struct {
    char pattern[MAX_LINE];
    char family[128];
    char description[256];
    int is_extension; /* 1 = match only as file extension, 0 = match anywhere */
} PatternEntry;

typedef struct {
    HashEntry *hashes;
    int hash_count;
    int hash_capacity;

    PatternEntry *patterns;
    int pattern_count;
    int pattern_capacity;

    char *whitelist[MAX_WHITELIST];
    int whitelist_count;

    unsigned long files_scanned;
    unsigned long dirs_scanned;
    unsigned long threats_found;
    unsigned long errors;
    double scan_time;
} ScannerState;

/* ========================== GLOBALS ========================== */

static ScannerState state = {0};
static int verbose = 0;
static int quiet = 0;
static int quick_mode = 0;
static int max_depth = 32;

/* ========================== HASH DATABASE ========================== */

/* Known malicious SHA-256 hashes from CISA advisories and threat intelligence */
static const char *default_hashes[] = {
    /* Black Basta */
    "17205c43189c22dfcb278f5cc45c2562f622b0b6280dcd43cc1d3c274095eb90",
    "b32daf27aa392d26bdf5faafbaae6b21cd6c918d461ff59f548a73d447a96dd9",
    "88c8b472108e0d79d16a1634499c1b45048a10a38ee799054414613cc9dccccc",
    "58ddbea084ce18cfb3439219ebcf2fc5c1605d2f6271610b1c7af77b8d0484bd",
    "39939eacfbc20a2607064994497e3e886c90cd97b25926478434f46c95bd8ead",
    "5b2178c7a0fd69ab00cef041f446e04098bbb397946eda3f6755f9d94d53c221",
    "51eb749d6cbd08baf9d43c2f83abd9d4d86eb5206f62ba43b768251a98ce9d3e",
    "5942143614d8ed34567ea472c2b819777edd25c00b3e1b13b1ae98d7f9e28d43",
    "05ebae760340fe44362ab7c8f70b2d89d6c9ba9b9ee8a9f747b2f19d326c3431",
    "a7b36482ba5bca7a143a795074c432ed627d6afa5bc64de97fa660faa852f1a6",
    /* BlackCat/ALPHV */
    "732e24cb5d7ab558effc6dc88854f756016352c923ff5155dcb2eece35c19bc0",
    NULL
};

static const char *default_hash_families[] = {
    "BlackBasta", "BlackBasta", "BlackBasta", "BlackBasta", "BlackBasta",
    "BlackBasta", "BlackBasta", "BlackBasta", "BlackBasta", "BlackBasta",
    "BlackCat_ALPHV",
    NULL
};

static const char *default_hash_descs[] = {
    "Black Basta ransomware payload",
    "Black Basta ransomware payload",
    "Black Basta ransomware payload",
    "Black Basta ransomware payload",
    "Black Basta ransomware payload",
    "Black Basta ransomware payload",
    "Black Basta ransomware payload",
    "Black Basta ransomware payload",
    "Black Basta ransomware payload",
    "Black Basta ransomware payload",
    "BlackCat ALPHV Anti-Virus Tools Killer",
    NULL
};

/* Known malicious filename patterns */
static const char *default_patterns[] = {
    /* Ransomware notes */
    "RECOVER-FILES",
    "DECRYPT-FILES",
    "README_DECRYPT",
    "HOW_TO_DECRYPT",
    "RECOVERY_FILE",
    "LOCKBIT",
    "BLACKCAT",
    "ALPHV",
    "ROYAL",
    "BLACKSUIT",
    "CONTI",
    "BIANLIAN",
    "CL0P",
    "PLAYCRYPT",
    "AKIRA",
    "INTERLOCK",
    "SNATCH",
    "AVOSLOCKER",
    "MEDUSA",
    "BLACKBASTA",
    /* Known malicious tools */
    "cobaltstrike",
    "cobalt_strike",
    "ligolo",
    "chisel",
    "stealbit",
    "mimikatz",
    "mimidrv",
    "mimilib",
    "procdump",
    "rclone",
    "ngrok",
    "anydesk",
    /* Known malicious extensions */
    ".lockbit",
    ".blackcat",
    ".alphv",
    ".royal",
    ".conti",
    ".bianlian",
    ".clop",
    ".encrypted",
    ".locked",
    ".crypto",
    ".crypt",
    ".ransom",
    /* Known malicious binaries */
    "tomcat.exe",
    "tomcat7.exe",
    "conhost.exe",
    "socks1.ps1",
    "vic64.ps1",
    "storm.exe",
    "human2.aspx",
    "guestaguest.aspx",
    NULL
};

static const char *default_pattern_families[] = {
    "RansomNote", "RansomNote", "RansomNote", "RansomNote", "RansomNote",
    "LockBit", "BlackCat", "BlackCat", "Royal", "Royal",
    "Conti", "BianLian", "CL0P", "Play", "Akira", "Interlock",
    "Snatch", "AvosLocker", "Medusa", "BlackBasta",
    "CobaltStrike", "CobaltStrike", "Ligolo", "Chisel", "StealBit",
    "Mimikatz", "Mimikatz", "Mimikatz", "ProcDump", "Rclone", "Ngrok", "AnyDesk",
    "LockBit", "BlackCat", "BlackCat", "Royal", "Conti",
    "BianLian", "CL0P", "Generic", "Generic", "Generic", "Generic", "Generic",
    "BlackCat", "BlackCat", "Royal", "Royal", "BlackCat", "Interlock", "CL0P", "CL0P",
    NULL
};

static const char *default_pattern_descs[] = {
    "Ransomware recovery note",
    "Ransomware recovery note",
    "Ransomware recovery note",
    "Ransomware recovery note",
    "Ransomware recovery note",
    "LockBit ransomware indicator",
    "BlackCat ransomware indicator",
    "ALPHV ransomware indicator",
    "Royal ransomware indicator",
    "BlackSuit ransomware indicator",
    "Conti ransomware indicator",
    "BianLian ransomware indicator",
    "CL0P ransomware indicator",
    "Play ransomware indicator",
    "Akira ransomware indicator",
    "Interlock ransomware indicator",
    "Snatch ransomware indicator",
    "AvosLocker ransomware indicator",
    "Medusa ransomware indicator",
    "Black Basta ransomware indicator",
    "Cobalt Strike C2 framework",
    "Cobalt Strike C2 framework",
    "Ligolo tunneling tool",
    "Chisel tunneling tool",
    "StealBit exfiltration tool",
    "Mimikatz credential theft",
    "Mimikatz credential theft",
    "Mimikatz credential theft",
    "ProcDump credential dumping",
    "Rclone data exfiltration",
    "Ngrok tunneling tool",
    "AnyDesk remote access",
    "LockBit encrypted file",
    "BlackCat encrypted file",
    "ALPHV encrypted file",
    "Royal encrypted file",
    "Conti encrypted file",
    "BianLian encrypted file",
    "CL0P encrypted file",
    "Generic encrypted file",
    "Generic encrypted file",
    "Generic encrypted file",
    "Generic encrypted file",
    "Generic encrypted file",
    "BlackCat C2 component",
    "BlackCat C2 component",
    "Royal backdoor",
    "Royal backdoor",
    "BlackCat loader",
    "Interlock agent",
    "CL0P web shell",
    "CL0P web shell",
    NULL
};

/* ========================== FUNCTION PROTOTYPES ========================== */

void load_default_hashes(void);
void load_default_patterns(void);
int load_hashes_from_file(const char *path);
int load_patterns_from_file(const char *path);
void free_state(void);
void sha256_file(const char *path, char *output);
int check_hash(const char *hash, char *family_out, char *desc_out);
int check_filename(const char *filename, char *family_out, char *desc_out);
int scan_file(const char *path);
int scan_directory(const char *path, int depth);
void print_report(void);
void print_banner(void);
void print_usage(const char *prog);
int is_excluded_path(const char *path);

/* ========================== IMPLEMENTATION ========================== */

void load_default_hashes(void) {
    for (int i = 0; default_hashes[i] != NULL; i++) {
        if (state.hash_count >= state.hash_capacity) {
            state.hash_capacity = state.hash_capacity ? state.hash_capacity * 2 : 256;
            state.hashes = realloc(state.hashes, state.hash_capacity * sizeof(HashEntry));
            if (!state.hashes) {
                fprintf(stderr, "ERROR: Memory allocation failed\n");
                exit(1);
            }
        }
        strncpy(state.hashes[state.hash_count].hash, default_hashes[i], 64);
        state.hashes[state.hash_count].hash[64] = '\0';
        strncpy(state.hashes[state.hash_count].family, default_hash_families[i], 127);
        state.hashes[state.hash_count].family[127] = '\0';
        strncpy(state.hashes[state.hash_count].description, default_hash_descs[i], 255);
        state.hashes[state.hash_count].description[255] = '\0';
        state.hash_count++;
    }
}

void load_default_patterns(void) {
    for (int i = 0; default_patterns[i] != NULL; i++) {
        if (state.pattern_count >= state.pattern_capacity) {
            state.pattern_capacity = state.pattern_capacity ? state.pattern_capacity * 2 : 128;
            state.patterns = realloc(state.patterns, state.pattern_capacity * sizeof(PatternEntry));
            if (!state.patterns) {
                fprintf(stderr, "ERROR: Memory allocation failed\n");
                exit(1);
            }
        }
        strncpy(state.patterns[state.pattern_count].pattern, default_patterns[i], MAX_LINE - 1);
        state.patterns[state.pattern_count].pattern[MAX_LINE - 1] = '\0';
        strncpy(state.patterns[state.pattern_count].family, default_pattern_families[i], 127);
        state.patterns[state.pattern_count].family[127] = '\0';
        strncpy(state.patterns[state.pattern_count].description, default_pattern_descs[i], 255);
        state.patterns[state.pattern_count].description[255] = '\0';
        /* Determine if this is an extension pattern (starts with .) */
        state.patterns[state.pattern_count].is_extension = (default_patterns[i][0] == '.') ? 1 : 0;
        state.pattern_count++;
    }
}

int load_hashes_from_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "WARNING: Cannot open hash file: %s\n", path);
        return -1;
    }

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;

        /* Parse: hash,family,description */
        char hash[65] = {0};
        char family[128] = {0};
        char desc[256] = {0};

        char *tok = strtok(line, ",");
        if (!tok) continue;
        strncpy(hash, tok, 64);
        hash[64] = '\0';

        tok = strtok(NULL, ",");
        if (tok) {
            strncpy(family, tok, 127);
            family[127] = '\0';
        } else {
            strcpy(family, "Unknown");
        }

        tok = strtok(NULL, "\n");
        if (tok) {
            strncpy(desc, tok, 255);
            desc[255] = '\0';
        } else {
            strcpy(desc, "No description");
        }

        if (state.hash_count >= state.hash_capacity) {
            state.hash_capacity = state.hash_capacity ? state.hash_capacity * 2 : 256;
            state.hashes = realloc(state.hashes, state.hash_capacity * sizeof(HashEntry));
            if (!state.hashes) {
                fprintf(stderr, "ERROR: Memory allocation failed\n");
                exit(1);
            }
        }

        strncpy(state.hashes[state.hash_count].hash, hash, 64);
        state.hashes[state.hash_count].hash[64] = '\0';
        strncpy(state.hashes[state.hash_count].family, family, 127);
        state.hashes[state.hash_count].family[127] = '\0';
        strncpy(state.hashes[state.hash_count].description, desc, 255);
        state.hashes[state.hash_count].description[255] = '\0';
        state.hash_count++;
    }

    fclose(f);
    if (!quiet) {
        printf("[*] Loaded %d hashes from %s\n", state.hash_count, path);
    }
    return 0;
}

int load_patterns_from_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "WARNING: Cannot open pattern file: %s\n", path);
        return -1;
    }

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;

        char pattern[MAX_LINE] = {0};
        char family[128] = {0};
        char desc[256] = {0};

        char *tok = strtok(line, ",");
        if (!tok) continue;
        strncpy(pattern, tok, MAX_LINE - 1);
        pattern[MAX_LINE - 1] = '\0';

        tok = strtok(NULL, ",");
        if (tok) {
            strncpy(family, tok, 127);
            family[127] = '\0';
        } else {
            strcpy(family, "Unknown");
        }

        tok = strtok(NULL, "\n");
        if (tok) {
            strncpy(desc, tok, 255);
            desc[255] = '\0';
        } else {
            strcpy(desc, "No description");
        }

        if (state.pattern_count >= state.pattern_capacity) {
            state.pattern_capacity = state.pattern_capacity ? state.pattern_capacity * 2 : 128;
            state.patterns = realloc(state.patterns, state.pattern_capacity * sizeof(PatternEntry));
            if (!state.patterns) {
                fprintf(stderr, "ERROR: Memory allocation failed\n");
                exit(1);
            }
        }

        strncpy(state.patterns[state.pattern_count].pattern, pattern, MAX_LINE - 1);
        state.patterns[state.pattern_count].pattern[MAX_LINE - 1] = '\0';
        strncpy(state.patterns[state.pattern_count].family, family, 127);
        state.patterns[state.pattern_count].family[127] = '\0';
        strncpy(state.patterns[state.pattern_count].description, desc, 255);
        state.patterns[state.pattern_count].description[255] = '\0';
        state.patterns[state.pattern_count].is_extension = (pattern[0] == '.') ? 1 : 0;
        state.pattern_count++;
    }

    fclose(f);
    if (!quiet) {
        printf("[*] Loaded %d patterns from %s\n", state.pattern_count, path);
    }
    return 0;
}

void free_state(void) {
    free(state.hashes);
    free(state.patterns);
    memset(&state, 0, sizeof(state));
}

void sha256_file(const char *path, char *output) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        output[0] = '\0';
        return;
    }

    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    unsigned char buf[BLOCK_SIZE];
    size_t n;
    while ((n = fread(buf, 1, BLOCK_SIZE, f)) > 0) {
        SHA256_Update(&ctx, buf, n);
    }
    fclose(f);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';
}

int check_hash(const char *hash, char *family_out, char *desc_out) {
    for (int i = 0; i < state.hash_count; i++) {
        if (strcasecmp(hash, state.hashes[i].hash) == 0) {
            if (family_out) strcpy(family_out, state.hashes[i].family);
            if (desc_out) strcpy(desc_out, state.hashes[i].description);
            return 1;
        }
    }
    return 0;
}

int check_filename(const char *filename, char *family_out, char *desc_out) {
    char lower_filename[MAX_PATH];
    strncpy(lower_filename, filename, MAX_PATH - 1);
    lower_filename[MAX_PATH - 1] = '\0';
    for (int i = 0; lower_filename[i]; i++) {
        lower_filename[i] = tolower(lower_filename[i]);
    }

    for (int i = 0; i < state.pattern_count; i++) {
        char lower_pattern[MAX_LINE];
        strncpy(lower_pattern, state.patterns[i].pattern, MAX_LINE - 1);
        lower_pattern[MAX_LINE - 1] = '\0';
        for (int j = 0; lower_pattern[j]; j++) {
            lower_pattern[j] = tolower(lower_pattern[j]);
        }

        int matched = 0;
        if (state.patterns[i].is_extension) {
            /* For extension patterns, check if filename ends with this extension */
            int fname_len = strlen(lower_filename);
            int pat_len = strlen(lower_pattern);
            if (fname_len >= pat_len) {
                if (strcmp(lower_filename + fname_len - pat_len, lower_pattern) == 0) {
                    matched = 1;
                }
            }
        } else {
            /* For regular patterns, check substring match */
            if (strstr(lower_filename, lower_pattern) != NULL) {
                matched = 1;
            }
        }

        if (matched) {
            if (family_out) strcpy(family_out, state.patterns[i].family);
            if (desc_out) strcpy(desc_out, state.patterns[i].description);
            return 1;
        }
    }
    return 0;
}

int scan_file(const char *path) {
    state.files_scanned++;

    /* Check filename first (fast) */
    const char *filename = strrchr(path, '/');
    filename = filename ? filename + 1 : path;

    char family[126], desc[256];
    int name_match = check_filename(filename, family, desc);

    /* In quick mode, skip hash if filename doesn't match */
    if (quick_mode && !name_match) {
        return 0;
    }

    /* Compute hash and check */
    char hash[65];
    sha256_file(path, hash);
    int hash_match = 0;
    if (hash[0] != '\0') {
        char h_family[128], h_desc[256];
        hash_match = check_hash(hash, h_family, h_desc);
    }

    if (name_match || hash_match) {
        state.threats_found++;
        printf("\n[!!!] THREAT DETECTED\n");
        printf("    Path:     %s\n", path);
        if (hash[0]) {
            printf("    SHA-256:  %s\n", hash);
        }
        if (name_match) {
            printf("    Match:    Filename pattern\n");
            printf("    Family:   %s\n", family);
            printf("    Details:  %s\n", desc);
        }
        if (hash_match) {
            printf("    Match:    Known malicious hash\n");
            printf("    Family:   %s\n", family);
            printf("    Details:  %s\n", desc);
        }
        printf("\n");
        return 1;
    }

    if (verbose) {
        printf("[OK] %s\n", path);
    }

    return 0;
}

int is_excluded_path(const char *path) {
    /* Skip virtual filesystems and special directories */
    if (strncmp(path, "/proc/", 6) == 0) return 1;
    if (strncmp(path, "/sys/", 5) == 0) return 1;
    if (strncmp(path, "/dev/", 5) == 0) return 1;
    if (strncmp(path, "/run/", 5) == 0) return 1;
    if (strncmp(path, "/snap/", 6) == 0) return 1;
    /* Skip common false positive directories */
    if (strstr(path, "/.git/") != NULL) return 1;
    if (strstr(path, "/node_modules/") != NULL) return 1;
    if (strstr(path, "/site-packages/") != NULL) return 1;
    if (strstr(path, "/.cache/") != NULL) return 1;
    if (strstr(path, "/.local/share/") != NULL) return 1;
    return 0;
}

int scan_directory(const char *path, int depth) {
    if (depth > max_depth) {
        fprintf(stderr, "WARNING: Max directory depth reached at %s\n", path);
        return 0;
    }

    DIR *dir = opendir(path);
    if (!dir) {
        state.errors++;
        if (verbose) {
            fprintf(stderr, "WARNING: Cannot open directory: %s\n", path);
        }
        return 0;
    }

    state.dirs_scanned++;

    struct dirent *entry;
    char full_path[MAX_PATH];

    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        /* Build full path */
        int len = snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        if (len >= (int)sizeof(full_path)) {
            fprintf(stderr, "WARNING: Path too long, skipping: %s/%s\n", path, entry->d_name);
            continue;
        }

        struct stat st;
        if (lstat(full_path, &st) != 0) {
            state.errors++;
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (!is_excluded_path(full_path)) {
                scan_directory(full_path, depth + 1);
            }
        } else if (S_ISREG(st.st_mode)) {
            /* Skip very large files (>100MB) to avoid long scan times */
            if (st.st_size > 100 * 1024 * 1024) {
                if (verbose) {
                    printf("[SKIP] %s (too large: %ld MB)\n", full_path, st.st_size / (1024*1024));
                }
                continue;
            }
            scan_file(full_path);
        }
        /* Skip symlinks, devices, etc. */
    }

    closedir(dir);
    return 0;
}

void print_banner(void) {
    printf("============================================================\n");
    printf("  IOC Scanner - Ransomware Threat Detection Tool\n");
    printf("  Version 1.0 | Compiled: " __DATE__ " " __TIME__ "\n");
    printf("============================================================\n\n");
}

void print_report(void) {
    printf("\n============================================================\n");
    printf("  SCAN REPORT\n");
    printf("============================================================\n");
    printf("  Files scanned:      %lu\n", state.files_scanned);
    printf("  Directories scanned:%lu\n", state.dirs_scanned);
    printf("  Threats found:      %lu\n", state.threats_found);
    printf("  Errors:             %lu\n", state.errors);
    printf("  Scan time:          %.2f seconds\n", state.scan_time);
    printf("  Hash database:      %d entries\n", state.hash_count);
    printf("  Pattern database:   %d entries\n", state.pattern_count);
    printf("============================================================\n");

    if (state.threats_found > 0) {
        printf("\n  [!] WARNING: %lu THREAT(S) DETECTED - Review above results\n", state.threats_found);
    } else {
        printf("\n  [OK] No threats detected\n");
    }
    printf("============================================================\n");
}

void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS] [PATH]\n\n", prog);
    printf("Options:\n");
    printf("  -h, --help          Show this help message\n");
    printf("  -v, --verbose       Show every file scanned\n");
    printf("  -q, --quiet         Suppress informational messages\n");
    printf("  -H, --hashes FILE   Load additional hashes from CSV file\n");
    printf("  -P, --patterns FILE Load additional patterns from CSV file\n");
    printf("  -d, --database DIR  Load all .csv files from directory\n");
    printf("  -s, --scan          Scan mode (default)\n");
    printf("  -Q, --quick         Quick mode: skip hash for files not matching name patterns\n");
    printf("  -D, --depth N       Max directory depth (default: 32)\n");
    printf("\n");
    printf("Arguments:\n");
    printf("  PATH                Directory or file to scan (default: /home)\n");
    printf("\n");
    printf("CSV Hash Format:     sha256_hash,family,description\n");
    printf("CSV Pattern Format:  pattern,family,description\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s /home/user\n", prog);
    printf("  %s -v /var/www\n", prog);
    printf("  %s -H hashes.csv -P patterns.csv /\n", prog);
    printf("  %s -d /etc/ioc_db/ /home\n", prog);
    printf("  %s -Q -D 10 /home\n", prog);
    printf("\n");
}

/* ========================== MAIN ========================== */

int main(int argc, char *argv[]) {
    const char *scan_path = "/home";
    const char *hash_file = NULL;
    const char *pattern_file = NULL;
    const char *db_dir = NULL;

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_banner();
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            quiet = 1;
        } else if (strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "--hashes") == 0) {
            if (i + 1 < argc) {
                hash_file = argv[++i];
            } else {
                fprintf(stderr, "ERROR: -H requires a file path\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-P") == 0 || strcmp(argv[i], "--patterns") == 0) {
            if (i + 1 < argc) {
                pattern_file = argv[++i];
            } else {
                fprintf(stderr, "ERROR: -P requires a file path\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--database") == 0) {
            if (i + 1 < argc) {
                db_dir = argv[++i];
            } else {
                fprintf(stderr, "ERROR: -d requires a directory path\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-Q") == 0 || strcmp(argv[i], "--quick") == 0) {
            quick_mode = 1;
        } else if (strcmp(argv[i], "-D") == 0 || strcmp(argv[i], "--depth") == 0) {
            if (i + 1 < argc) {
                max_depth = atoi(argv[++i]);
            } else {
                fprintf(stderr, "ERROR: -D requires a number\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--scan") == 0) {
            /* Default mode, no-op */
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "ERROR: Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        } else {
            scan_path = argv[i];
        }
    }

    if (!quiet) {
        print_banner();
    }

    /* Load default IOC databases */
    load_default_hashes();
    load_default_patterns();

    if (!quiet) {
        printf("[*] Loaded %d default hashes\n", state.hash_count);
        printf("[*] Loaded %d default patterns\n", state.pattern_count);
    }

    /* Load custom hash file if provided */
    if (hash_file) {
        load_hashes_from_file(hash_file);
    }

    /* Load custom pattern file if provided */
    if (pattern_file) {
        load_patterns_from_file(pattern_file);
    }

    /* Load all CSV files from database directory */
    if (db_dir) {
        DIR *d = opendir(db_dir);
        if (!d) {
            fprintf(stderr, "WARNING: Cannot open database directory: %s\n", db_dir);
        } else {
            struct dirent *ent;
            char dbpath[MAX_PATH];
            while ((ent = readdir(d)) != NULL) {
                const char *ext = strrchr(ent->d_name, '.');
                if (ext && strcmp(ext, ".csv") == 0) {
                    snprintf(dbpath, sizeof(dbpath), "%s/%s", db_dir, ent->d_name);
                    if (strstr(ent->d_name, "hash") || strstr(ent->d_name, "Hash")) {
                        load_hashes_from_file(dbpath);
                    } else if (strstr(ent->d_name, "pattern") || strstr(ent->d_name, "Pattern")) {
                        load_patterns_from_file(dbpath);
                    } else {
                        /* Try both */
                        load_hashes_from_file(dbpath);
                        load_patterns_from_file(dbpath);
                    }
                }
            }
            closedir(d);
        }
    }

    if (!quiet) {
        printf("[*] Total hashes in database: %d\n", state.hash_count);
        printf("[*] Total patterns in database: %d\n", state.pattern_count);
        printf("[*] Starting scan of: %s\n\n", scan_path);
    }

    /* Start scan */
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    struct stat st;
    if (stat(scan_path, &st) != 0) {
        fprintf(stderr, "ERROR: Cannot access path: %s\n", scan_path);
        free_state();
        return 1;
    }

    if (S_ISDIR(st.st_mode)) {
        scan_directory(scan_path, 0);
    } else if (S_ISREG(st.st_mode)) {
        scan_file(scan_path);
    } else {
        fprintf(stderr, "ERROR: Path is not a file or directory: %s\n", scan_path);
        free_state();
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    state.scan_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    if (!quiet) {
        print_report();
    }

    free_state();
    return (state.threats_found > 0) ? 2 : 0;
}
