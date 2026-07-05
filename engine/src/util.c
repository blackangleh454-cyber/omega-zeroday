/**
 * omega_engine — Utility Functions
 * 
 * Base64, URL encoding, JSON parsing, hashing, timing, logging, threading.
 * All functions match omega.h public API declarations.
 * 
 * Copyright (c) 2026 Ghost Killer Omega — MIT License
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>
#include <math.h>
#include <pthread.h>
#include <sys/time.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/buffer.h>

#include "../include/omega.h"

/* Log levels (not in public header) */

/* Forward declaration for internal thread pool worker */
static void *tp_worker(void *arg);

/* ═══════════════════════════════════════════════════════════════
 *  SEVERITY / FINDING TYPE HELPERS
 * ═══════════════════════════════════════════════════════════════ */

const char *severity_str(severity_t sev) {
    switch (sev) {
        case SEV_INFO:     return "INFO";
        case SEV_LOW:      return "LOW";
        case SEV_MEDIUM:   return "MEDIUM";
        case SEV_HIGH:     return "HIGH";
        case SEV_CRITICAL: return "CRITICAL";
        default:           return "UNKNOWN";
    }
}

const char *severity_color(severity_t sev) {
    switch (sev) {
        case SEV_INFO:     return "\033[36m";    /* Cyan */
        case SEV_LOW:      return "\033[33m";    /* Yellow */
        case SEV_MEDIUM:   return "\033[93m";    /* Light yellow */
        case SEV_HIGH:     return "\033[91m";    /* Light red */
        case SEV_CRITICAL: return "\033[31m";    /* Red */
        default:           return "\033[0m";     /* Reset */
    }
}

const char *finding_type_str(finding_type_t type) {
    switch (type) {
        case FIND_AUTH_BYPASS:          return "AUTH_BYPASS";
        case FIND_JWT_WEAK_SECRET:      return "JWT_WEAK_SECRET";
        case FIND_JWT_ALG_NONE:         return "JWT_ALG_NONE";
        case FIND_JWT_KEY_CONFUSION:    return "JWT_KEY_CONFUSION";
        case FIND_HEADER_INJECTION:     return "HEADER_INJECTION";
        case FIND_PATH_TRAVERSAL:       return "PATH_TRAVERSAL";
        case FIND_METHOD_BYPASS:        return "METHOD_BYPASS";
        case FIND_RACE_CONDITION:       return "RACE_CONDITION";
        case FIND_RACE_DOUBLE_EXEC:     return "RACE_DOUBLE_EXEC";
        case FIND_RACE_TOKEN_REUSE:     return "RACE_TOKEN_REUSE";
        case FIND_RACE_COUPON_REUSE:    return "RACE_COUPON_REUSE";
        case FIND_SSRF_BASIC:           return "SSRF_BASIC";
        case FIND_SSRF_REDIRECT:        return "SSRF_REDIRECT";
        case FIND_SSRF_CLOUD_METADATA:  return "SSRF_CLOUD_METADATA";
        case FIND_SSRF_INTERNAL_PORT:   return "SSRF_INTERNAL_PORT";
        case FIND_SSRF_PROTO_SMUGGLE:   return "SSRF_PROTO_SMUGGLE";
        case FIND_SMUGGLE_CLTE:         return "SMUGGLE_CLTE";
        case FIND_SMUGGLE_TECL:         return "SMUGGLE_TECL";
        case FIND_SMUGGLE_TETE:         return "SMUGGLE_TETE";
        case FIND_MASS_ASSIGN:          return "MASS_ASSIGN";
        case FIND_MASS_HIDDEN_PARAM:    return "MASS_HIDDEN_PARAM";
        case FIND_MASS_CONTENT_TYPE:    return "MASS_CONTENT_TYPE";
        case FIND_LOGIC_NEGATIVE:       return "LOGIC_NEGATIVE";
        case FIND_LOGIC_OVERFLOW:       return "LOGIC_OVERFLOW";
        case FIND_LOGIC_TYPE_CONFUSION: return "LOGIC_TYPE_CONFUSION";
        case FIND_LOGIC_RATE_BYPASS:    return "LOGIC_RATE_BYPASS";
        case FIND_LOGIC_STATE_BYPASS:   return "LOGIC_STATE_BYPASS";
        case FIND_CRYPTO_ECB:           return "CRYPTO_ECB";
        case FIND_CRYPTO_WEAK_HASH:     return "CRYPTO_WEAK_HASH";
        case FIND_CRYPTO_TIMING:        return "CRYPTO_TIMING";
        case FIND_CRYPTO_TLS_WEAK:      return "CRYPTO_TLS_WEAK";
        case FIND_CRYPTO_PADDING_ORACLE:return "CRYPTO_PADDING_ORACLE";
        case FIND_XSS_REFLECTED:        return "XSS_REFLECTED";
        case FIND_XSS_STORED:           return "XSS_STORED";
        case FIND_XSS_DOM:              return "XSS_DOM";
        case FIND_SQLI_ERROR:           return "SQLI_ERROR";
        case FIND_SQLI_BLIND:           return "SQLI_BLIND";
        case FIND_SQLI_TIME:            return "SQLI_TIME";
        case FIND_LFI_TRAVERSAL:        return "LFI_TRAVERSAL";
        case FIND_LFI_NULL_BYTE:        return "LFI_NULL_BYTE";
        case FIND_LFI_PHP_WRAPPER:      return "LFI_PHP_WRAPPER";
        case FIND_CORS_MISCONFIG:       return "CORS_MISCONFIG";
        case FIND_OPEN_REDIRECT:        return "OPEN_REDIRECT";
        case FIND_HOST_HEADER_INJECTION:return "HOST_HEADER_INJECTION";
        case FIND_CRLF_INJECTION:       return "CRLF_INJECTION";
        case FIND_DIR_LISTING:          return "DIR_LISTING";
        case FIND_SENSITIVE_FILE:       return "SENSITIVE_FILE";
        case FIND_INFO_DISCLOSURE:      return "INFO_DISCLOSURE";
        case FIND_GRAPHQL_INTROSPECTION:return "GRAPHQL_INTROSPECTION";
        case FIND_WEBSOCKET_HIJACK:     return "WEBSOCKET_HIJACK";
        default:                        return "UNKNOWN";
    }
}

/* ═══════════════════════════════════════════════════════════════
 *  LOGGING
 * ═══════════════════════════════════════════════════════════════ */

static int g_log_level = LOG_INFO;

void log_info(const char *fmt, ...) {
    if (g_log_level > LOG_INFO) return;
    va_list args;
    va_start(args, fmt);
    printf("\033[36m[INFO]\033[0m  ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

void log_warning(const char *fmt, ...) {
    if (g_log_level > LOG_WARN) return;
    va_list args;
    va_start(args, fmt);
    printf("\033[33m[WARN]\033[0m  ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

void log_error(const char *fmt, ...) {
    if (g_log_level > LOG_ERROR) return;
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "\033[91m[ERROR]\033[0m ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

void log_verbose(const char *fmt, ...) {
    if (g_log_level > LOG_VERBOSE) return;
    va_list args;
    va_start(args, fmt);
    printf("\033[90m[VERB]\033[0m  ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

/* ═══════════════════════════════════════════════════════════════
 *  BASE64 ENCODING/DECODING
 * ═══════════════════════════════════════════════════════════════ */

int base64_encode(const unsigned char *data, int len, char *out, int out_len) {
    if (!data || !out || out_len <= 0) return -1;
    
    BIO *bio, *b64;
    BUF_MEM *bptr;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data, len);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    
    int copy_len = (int)bptr->length;
    if (copy_len >= out_len) copy_len = out_len - 1;
    memcpy(out, bptr->data, copy_len);
    out[copy_len] = '\0';
    
    BIO_free_all(b64);
    return copy_len;
}

int base64_decode(const char *data, unsigned char *out, int out_len) {
    if (!data || !out || out_len <= 0) return -1;
    
    int data_len = (int)strlen(data);
    BIO *b64, *bio;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(data, data_len);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    int decode_len = BIO_read(bio, out, out_len);
    BIO_free_all(bio);
    
    if (decode_len < 0) return -1;
    out[decode_len] = '\0';
    return decode_len;
}

int base64_url_encode(const unsigned char *data, int len, char *out, int out_len) {
    int enc_len = base64_encode(data, len, out, out_len);
    if (enc_len < 0) return -1;
    
    /* Convert to URL-safe base64 */
    for (int i = 0; i < enc_len; i++) {
        if (out[i] == '+') out[i] = '-';
        else if (out[i] == '/') out[i] = '_';
        else if (out[i] == '=') out[i] = '\0';  /* Strip padding */
    }
    
    return (int)strlen(out);
}

int base64_url_decode(const char *data, unsigned char *out, int out_len) {
    if (!data || !out || out_len <= 0) return -1;
    
    int data_len = (int)strlen(data);
    char *padded = malloc(data_len + 4);
    if (!padded) return -1;
    
    memcpy(padded, data, data_len);
    padded[data_len] = '\0';
    
    /* Convert URL-safe base64 to standard */
    for (int i = 0; i < data_len; i++) {
        if (padded[i] == '-') padded[i] = '+';
        else if (padded[i] == '_') padded[i] = '/';
    }
    
    /* Add padding */
    int padding = (4 - (data_len % 4)) % 4;
    for (int i = 0; i < padding; i++) {
        padded[data_len + i] = '=';
    }
    padded[data_len + padding] = '\0';
    
    int result = base64_decode(padded, out, out_len);
    free(padded);
    return result;
}

/* ═══════════════════════════════════════════════════════════════
 *  URL ENCODING/DECODING
 * ═══════════════════════════════════════════════════════════════ */

int url_encode(const char *str, char *out, int out_len) {
    if (!str || !out || out_len <= 0) return -1;
    
    int j = 0;
    for (int i = 0; str[i] && j < out_len - 3; i++) {
        unsigned char c = (unsigned char)str[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out[j++] = (char)c;
        } else {
            j += snprintf(out + j, out_len - j, "%%%02X", c);
        }
    }
    out[j] = '\0';
    return j;
}

int url_decode(const char *str, char *out, int out_len) {
    if (!str || !out || out_len <= 0) return -1;
    
    int j = 0;
    for (int i = 0; str[i] && j < out_len - 1; i++) {
        if (str[i] == '%' && str[i+1] && str[i+2]) {
            char hex[3] = {str[i+1], str[i+2], '\0'};
            out[j++] = (char)strtol(hex, NULL, 16);
            i += 2;
        } else if (str[i] == '+') {
            out[j++] = ' ';
        } else {
            out[j++] = str[i];
        }
    }
    out[j] = '\0';
    return j;
}

/* ═══════════════════════════════════════════════════════════════
 *  JSON HELPERS
 * ═══════════════════════════════════════════════════════════════ */

char *json_get_value(const char *json, const char *key, char *val, int val_len) {
    if (!json || !key || !val || val_len <= 0) return NULL;
    
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    
    const char *pos = strstr(json, search);
    if (!pos) return NULL;
    
    pos += strlen(search);
    while (*pos && (*pos == ' ' || *pos == ':')) pos++;
    
    if (*pos == '"') {
        pos++;
        const char *end = strchr(pos, '"');
        if (!end) return NULL;
        int copy_len = (int)(end - pos);
        if (copy_len >= val_len) copy_len = val_len - 1;
        strncpy(val, pos, copy_len);
        val[copy_len] = '\0';
    } else {
        /* Non-string value */
        const char *end = pos;
        while (*end && *end != ',' && *end != '}' && *end != ']') end++;
        int copy_len = (int)(end - pos);
        if (copy_len >= val_len) copy_len = val_len - 1;
        strncpy(val, pos, copy_len);
        val[copy_len] = '\0';
    }
    
    return val;
}

bool json_has_key(const char *json, const char *key) {
    if (!json || !key) return false;
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    return strstr(json, search) != NULL;
}

/* ═══════════════════════════════════════════════════════════════
 *  STRING HELPERS
 * ═══════════════════════════════════════════════════════════════ */

bool str_contains(const char *haystack, const char *needle) {
    if (!haystack || !needle) return false;
    return strstr(haystack, needle) != NULL;
}

bool str_contains_ci(const char *haystack, const char *needle) {
    if (!haystack || !needle) return false;
    
    int needle_len = (int)strlen(needle);
    int haystack_len = (int)strlen(haystack);
    
    if (needle_len > haystack_len) return false;
    
    for (int i = 0; i <= haystack_len - needle_len; i++) {
        bool match = true;
        for (int j = 0; j < needle_len; j++) {
            if (tolower((unsigned char)haystack[i+j]) != 
                tolower((unsigned char)needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

char *str_skip_whitespace(char *s) {
    if (!s) return NULL;
    while (*s && (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r')) s++;
    return s;
}

int str_count_char(const char *str, char c) {
    if (!str) return 0;
    int count = 0;
    for (const char *p = str; *p; p++) {
        if (*p == c) count++;
    }
    return count;
}

/* ═══════════════════════════════════════════════════════════════
 *  HASHING (OpenSSL)
 * ═══════════════════════════════════════════════════════════════ */

bool md5_hash(const char *data, char *out, int out_len) {
    if (!data || !out || out_len < 33) return false;
    
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char *)data, strlen(data), digest);
    
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(out + (i * 2), "%02x", digest[i]);
    }
    out[32] = '\0';
    return true;
}

bool sha1_hash(const char *data, char *out, int out_len) {
    if (!data || !out || out_len < 41) return false;
    
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)data, strlen(data), digest);
    
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(out + (i * 2), "%02x", digest[i]);
    }
    out[40] = '\0';
    return true;
}

bool sha256_hash(const char *data, char *out, int out_len) {
    if (!data || !out || out_len < 65) return false;
    
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)data, strlen(data), digest);
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(out + (i * 2), "%02x", digest[i]);
    }
    out[64] = '\0';
    return true;
}

bool hmac_sha256(const char *key, int key_len, const char *data, int data_len, char *out, int out_len) {
    if (!key || !data || !out || out_len < 65) return false;
    
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    
    HMAC(EVP_sha256(), key, key_len, (unsigned char *)data, data_len, digest, &digest_len);
    
    for (unsigned int i = 0; i < digest_len; i++) {
        sprintf(out + (i * 2), "%02x", digest[i]);
    }
    out[digest_len * 2] = '\0';
    return true;
}

/* ═══════════════════════════════════════════════════════════════
 *  TIMING
 * ═══════════════════════════════════════════════════════════════ */

double time_now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}

double time_diff_ms(double start, double end) {
    return (end - start) * 1000.0;
}

/* ═══════════════════════════════════════════════════════════════
 *  CHAIN ANALYSIS — Link related findings into attack chains
 * ═══════════════════════════════════════════════════════════════ */

int chain_analyze(scan_context_t *ctx) {
    if (!ctx || ctx->finding_count < 2) return 0;
    
    int chains_found = 0;
    
    /* Simple chain detection: group findings by URL, look for multi-step attacks */
    for (int i = 0; i < ctx->finding_count && chains_found < 16; i++) {
        finding_t *fi = &ctx->findings[i];
        
        /* Start a chain with this finding */
        chain_t *chain = &ctx->chains[chains_found];
        memset(chain, 0, sizeof(chain_t));
        chain->steps[0] = *fi;
        chain->step_count = 1;
        chain->combined_severity = fi->severity;
        chain->combined_cvss = fi->cvss_score;
        
        /* Look for related findings on the same URL or with related types */
        for (int j = i + 1; j < ctx->finding_count && chain->step_count < 8; j++) {
            finding_t *fj = &ctx->findings[j];
            
            /* Same URL = likely part of same attack chain */
            bool same_url = (strcmp(fi->url, fj->url) == 0);
            
            /* Related types: auth bypass + race condition = account takeover chain */
            bool related = false;
            if (fi->type == FIND_AUTH_BYPASS && fj->type == FIND_RACE_CONDITION) related = true;
            if (fi->type == FIND_JWT_ALG_NONE && fj->type == FIND_MASS_ASSIGN) related = true;
            if (fi->type == FIND_SSRF_BASIC && fj->type == FIND_PATH_TRAVERSAL) related = true;
            if (fi->type == FIND_LOGIC_NEGATIVE && fj->type == FIND_LOGIC_OVERFLOW) related = true;
            if (fi->type == FIND_CRYPTO_WEAK_HASH && fj->type == FIND_CRYPTO_TIMING) related = true;
            
            if (same_url || related) {
                chain->steps[chain->step_count++] = *fj;
                
                /* Combined severity = worst of the two */
                if (fj->severity < chain->combined_severity) {
                    chain->combined_severity = fj->severity;
                }
                
                /* Combined CVSS = max of the two */
                if (fj->cvss_score > chain->combined_cvss) {
                    chain->combined_cvss = fj->cvss_score;
                }
            }
        }
        
        /* Only create chain if it has more than 1 step */
        if (chain->step_count > 1) {
            snprintf(chain->description, sizeof(chain->description),
                "Attack chain: %s → %s (%d steps)",
                finding_type_str(chain->steps[0].type),
                finding_type_str(chain->steps[chain->step_count - 1].type),
                chain->step_count);
            
            chains_found++;
            ctx->chain_count = chains_found;
            
            log_info("⛓️  Chain #%d: %s → %s (%d steps, CVSS %.1f)",
                chains_found,
                finding_type_str(chain->steps[0].type),
                finding_type_str(chain->steps[chain->step_count - 1].type),
                chain->step_count,
                chain->combined_cvss);
        } else {
            /* Reset — not a real chain */
            memset(chain, 0, sizeof(chain_t));
        }
    }
    
    return chains_found;
}

/* ═══════════════════════════════════════════════════════════════
 *  THREAD POOL (simple implementation matching header)
 * ═══════════════════════════════════════════════════════════════ */

/* Internal work queue (not exposed in header) */
typedef struct tp_work {
    thread_func_t func;
    void *arg;
    struct tp_work *next;
} tp_work_t;

typedef struct {
    tp_work_t *head;
    tp_work_t *tail;
    int active_count;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool shutdown;
} tp_internal_t;

static tp_internal_t g_tp_internal;

/* Thread pool worker function */
static void *tp_worker(void *arg) {
    thread_pool_t *pool = (thread_pool_t *)arg;
    tp_internal_t *ti = &g_tp_internal;
    (void)pool;
    
    while (1) {
        pthread_mutex_lock(&ti->mutex);
        
        while (!ti->head && !ti->shutdown) {
            pthread_cond_wait(&ti->cond, &ti->mutex);
        }
        
        if (ti->shutdown) {
            pthread_mutex_unlock(&ti->mutex);
            break;
        }
        
        tp_work_t *work = ti->head;
        if (work) {
            ti->head = work->next;
            if (!ti->head) ti->tail = NULL;
        }
        pthread_mutex_unlock(&ti->mutex);
        
        if (work) {
            work->func(work->arg);
            free(work);
            
            pthread_mutex_lock(&ti->mutex);
            ti->active_count--;
            if (ti->active_count == 0 && !ti->head) {
                pthread_cond_broadcast(&ti->cond);
            }
            pthread_mutex_unlock(&ti->mutex);
        }
    }
    
    return NULL;
}

int thread_pool_init(thread_pool_t *pool, int count) {
    if (!pool || count <= 0 || count > OMEGA_MAX_THREADS) return -1;
    
    memset(pool, 0, sizeof(thread_pool_t));
    pool->thread_count = count;
    pool->running = true;
    
    memset(&g_tp_internal, 0, sizeof(tp_internal_t));
    pthread_mutex_init(&g_tp_internal.mutex, NULL);
    pthread_cond_init(&g_tp_internal.cond, NULL);
    
    for (int i = 0; i < count; i++) {
        pthread_create(&pool->threads[i], NULL, tp_worker, pool);
    }
    
    return 0;
}

int thread_pool_submit(thread_pool_t *pool, thread_func_t func, void *arg) {
    if (!pool || !func) return -1;
    
    tp_work_t *work = malloc(sizeof(tp_work_t));
    if (!work) return -1;
    work->func = func;
    work->arg = arg;
    work->next = NULL;
    
    pthread_mutex_lock(&g_tp_internal.mutex);
    if (g_tp_internal.tail) {
        g_tp_internal.tail->next = work;
        g_tp_internal.tail = work;
    } else {
        g_tp_internal.head = work;
        g_tp_internal.tail = work;
    }
    g_tp_internal.active_count++;
    pthread_cond_signal(&g_tp_internal.cond);
    pthread_mutex_unlock(&g_tp_internal.mutex);
    
    return 0;
}

void thread_pool_wait(thread_pool_t *pool) {
    if (!pool) return;
    
    pthread_mutex_lock(&g_tp_internal.mutex);
    while (g_tp_internal.head || g_tp_internal.active_count > 0) {
        pthread_cond_wait(&g_tp_internal.cond, &g_tp_internal.mutex);
    }
    pthread_mutex_unlock(&g_tp_internal.mutex);
}

void thread_pool_destroy(thread_pool_t *pool) {
    if (!pool) return;
    
    pthread_mutex_lock(&g_tp_internal.mutex);
    g_tp_internal.shutdown = true;
    pthread_cond_broadcast(&g_tp_internal.cond);
    pthread_mutex_unlock(&g_tp_internal.mutex);
    
    for (int i = 0; i < pool->thread_count; i++) {
        pthread_join(pool->threads[i], NULL);
    }
    
    while (g_tp_internal.head) {
        tp_work_t *w = g_tp_internal.head;
        g_tp_internal.head = w->next;
        free(w);
    }
    
    pool->running = false;
    pthread_mutex_destroy(&g_tp_internal.mutex);
    pthread_cond_destroy(&g_tp_internal.cond);
    memset(&g_tp_internal, 0, sizeof(tp_internal_t));
}

void log_set_level(int level) {
    g_log_level = level;
}

int log_get_level(void) {
    return g_log_level;
}
