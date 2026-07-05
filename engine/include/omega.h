/*
 * OMEGA-ZERODAY HUNTER v2.0 — Core Header
 * 
 * A production-grade 0-day vulnerability discovery engine.
 * Written in C for maximum speed and precision.
 * 
 * Author: Ghost Killer Omega / Mirzacyberhub
 * License: MIT
 * 
 * "Every wall has a crack. Every cipher has a weakness.
 *  Every secure thing has a side-channel." — Ghost Killer
 */

#ifndef OMEGA_H
#define OMEGA_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/* ============================================================
 * VERSION & CONSTANTS
 * ============================================================ */

#define OMEGA_VERSION      "2.0.0"
#define OMEGA_NAME         "OMEGA-ZERODAY HUNTER"
#define OMEGA_AUTHOR       "Ghost Killer Omega"
#define OMEGA_MAX_THREADS  16
#define OMEGA_MAX_ENDPOINTS 200
#define OMEGA_MAX_FINDINGS  200
#define OMEGA_MAX_HEADER_LEN 2048
#define OMEGA_MAX_BODY_LEN   1048576  /* 1MB */
#define OMEGA_DEFAULT_TIMEOUT 10
#define OMEGA_DEFAULT_THREADS 20
#define OMEGA_MAX_URL_LEN     2048
#define OMEGA_MAX_PATH_LEN    1024
#define OMEGA_MAX_HOST_LEN    256
#define OMEGA_DEFAULT_PORT    80

/* ============================================================
 * ENUMS
 * ============================================================ */

typedef enum {
    SEV_CRITICAL = 0,
    SEV_HIGH     = 1,
    SEV_MEDIUM   = 2,
    SEV_LOW      = 3,
    SEV_INFO     = 4
} severity_t;

enum { LOG_VERBOSE = 0, LOG_INFO, LOG_WARN, LOG_ERROR, LOG_FATAL };

typedef enum {
    ENGINE_RECON      = (1 << 0),
    ENGINE_AUTH       = (1 << 1),
    ENGINE_RACE       = (1 << 2),
    ENGINE_SSRF       = (1 << 3),
    ENGINE_MASS       = (1 << 4),
    ENGINE_SMUGGLE    = (1 << 5),
    ENGINE_LOGIC      = (1 << 6),
    ENGINE_CRYPTO     = (1 << 7),
    ENGINE_ALL        = 0xFF
} engine_mask_t;

typedef enum {
    FIND_AUTH_BYPASS,
    FIND_JWT_WEAK_SECRET,
    FIND_JWT_ALG_NONE,
    FIND_JWT_KEY_CONFUSION,
    FIND_HEADER_INJECTION,
    FIND_PATH_TRAVERSAL,
    FIND_METHOD_BYPASS,
    FIND_RACE_CONDITION,
    FIND_RACE_DOUBLE_EXEC,
    FIND_RACE_TOKEN_REUSE,
    FIND_RACE_COUPON_REUSE,
    FIND_SSRF_BASIC,
    FIND_SSRF_REDIRECT,
    FIND_SSRF_CLOUD_METADATA,
    FIND_SSRF_INTERNAL_PORT,
    FIND_SSRF_PROTO_SMUGGLE,
    FIND_SMUGGLE_CLTE,
    FIND_SMUGGLE_TECL,
    FIND_SMUGGLE_TETE,
    FIND_MASS_ASSIGN,
    FIND_MASS_HIDDEN_PARAM,
    FIND_MASS_CONTENT_TYPE,
    FIND_LOGIC_NEGATIVE,
    FIND_LOGIC_OVERFLOW,
    FIND_LOGIC_TYPE_CONFUSION,
    FIND_LOGIC_RATE_BYPASS,
    FIND_LOGIC_STATE_BYPASS,
    FIND_CRYPTO_ECB,
    FIND_CRYPTO_WEAK_HASH,
    FIND_CRYPTO_TIMING,
    FIND_CRYPTO_TLS_WEAK,
    FIND_CRYPTO_PADDING_ORACLE,
    FIND_XSS_REFLECTED,
    FIND_XSS_STORED,
    FIND_XSS_DOM,
    FIND_SQLI_ERROR,
    FIND_SQLI_BLIND,
    FIND_SQLI_TIME,
    FIND_LFI_TRAVERSAL,
    FIND_LFI_NULL_BYTE,
    FIND_LFI_PHP_WRAPPER,
    FIND_CORS_MISCONFIG,
    FIND_OPEN_REDIRECT,
    FIND_HOST_HEADER_INJECTION,
    FIND_CRLF_INJECTION,
    FIND_DIR_LISTING,
    FIND_SENSITIVE_FILE,
    FIND_INFO_DISCLOSURE,
    FIND_GRAPHQL_INTROSPECTION,
    FIND_WEBSOCKET_HIJACK,
    FIND_PROTO_POLLUTION,
    FIND_CHAIN_MULTI_STEP
} finding_type_t;

typedef enum {
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_PATCH,
    HTTP_HEAD,
    HTTP_OPTIONS,
    HTTP_TRACE
} http_method_t;

/* ============================================================
 * DATA STRUCTURES
 * ============================================================ */

/* HTTP Request */
typedef struct {
    char url[OMEGA_MAX_URL_LEN];
    char host[OMEGA_MAX_HOST_LEN];
    char path[OMEGA_MAX_PATH_LEN];
    int  port;
    bool ssl;
    http_method_t method;
    char headers[4096];
    char *body;
    int  body_len;
    char cookie[2048];
    char auth_header[512];
    int  timeout;
} http_request_t;

/* HTTP Response */
typedef struct {
    int  status_code;
    char status_text[128];
    char headers[OMEGA_MAX_HEADER_LEN];
    char *body;
    int  body_len;
    char content_type[256];
    char server[256];
    char set_cookie[2048];
    char location[OMEGA_MAX_URL_LEN];
    double response_time;
    bool timed_out;
    bool connection_error;
} http_response_t;

/* Endpoint */
typedef struct {
    char url[OMEGA_MAX_URL_LEN];
    char path[OMEGA_MAX_PATH_LEN];
    int  status_code;
    char content_type[256];
    int  content_length;
    char title[512];
    bool has_auth;
    bool has_params;
    bool has_forms;
    bool has_api;
    bool is_json;
    char methods[256];       /* Available HTTP methods */
    char headers[OMEGA_MAX_HEADER_LEN];
} endpoint_t;

/* Finding */
typedef struct {
    finding_type_t type;
    severity_t severity;
    char url[OMEGA_MAX_URL_LEN];
    char description[1024];
    char evidence[2048];
    char remediation[512];
    float confidence;       /* 0.0 - 1.0 */
    float cvss_score;       /* 0.0 - 10.0 */
    char cwe_id[32];
    char engine[64];
    double timestamp;
} finding_t;

/* Chain (multi-step vulnerability) */
typedef struct {
    finding_t steps[8];
    int  step_count;
    char description[2048];
    severity_t combined_severity;
    float combined_cvss;
} chain_t;

/* Scan Context */
typedef struct {
    char target_url[OMEGA_MAX_URL_LEN];
    char target_host[OMEGA_MAX_HOST_LEN];
    int  target_port;
    bool target_ssl;
    char base_url[OMEGA_MAX_URL_LEN];
    
    endpoint_t endpoints[OMEGA_MAX_ENDPOINTS];
    int endpoint_count;
    
    finding_t findings[OMEGA_MAX_FINDINGS];
    int finding_count;
    
    chain_t chains[16];
    int chain_count;
    
    int threads;
    int timeout;
    int engines;
    char cookie[2048];
    char auth_token[512];
    char user_agent[256];
    
    /* Stats */
    int total_requests;
    double total_time;
    int endpoints_discovered;
    int critical_count;
    int high_count;
    int medium_count;
    int low_count;
    
    /* Progress (for UI callback) */
    void (*progress_callback)(const char *engine, int current, int total, const char *msg);
    void (*finding_callback)(const finding_t *finding);
    void (*phase_callback)(int phase, int total_phases, const char *name);
    
    pthread_mutex_t mutex;
} scan_context_t;

/* URL parsed components */
typedef struct {
    char scheme[16];
    char host[OMEGA_MAX_HOST_LEN];
    int  port;
    char path[OMEGA_MAX_PATH_LEN];
    char query[2048];
    char fragment[256];
    bool ssl;
} parsed_url_t;

/* JWT Token */
typedef struct {
    char header_b64[512];
    char payload_b64[2048];
    char signature_b64[512];
    char header_json[1024];
    char payload_json[4096];
    char algorithm[64];
    bool is_valid;
    bool is_empty_sig;
} jwt_token_t;

/* Timing measurement */
typedef struct {
    double times[32];
    int count;
    double mean;
    double stddev;
    double min;
    double max;
    bool anomaly_detected;
} timing_sample_t;

/* SSRF payload */
typedef struct {
    char payload[256];
    char description[128];
    char expected_indicator[128];
    char protocol[16];
} ssrf_payload_t;

/* Race condition test */
typedef struct {
    char url[OMEGA_MAX_URL_LEN];
    http_method_t method;
    char headers[2048];
    char body[4096];
    int burst_count;
    double max_time_diff;
} race_test_t;

/* Smuggle payload */
typedef struct {
    char name[64];
    char payload[2048];
    char detection_method[128];
    char expected_cl[32];
} smuggle_payload_t;

/* Crypto analysis */
typedef struct {
    char name[128];
    severity_t severity;
    char details[1024];
    float confidence;
} crypto_finding_t;

/* ============================================================
 * HTTP CLIENT (http.c)
 * ============================================================ */

/* Initialize HTTP client */
int http_init(void);

/* Cleanup HTTP client */
void http_cleanup(void);

/* Perform HTTP request */
int http_request(const http_request_t *req, http_response_t *resp);

/* Parse URL into components */
int url_parse(const char *url, parsed_url_t *out);

/* Build full URL from components */
int url_build(const parsed_url_t *parsed, char *out, int out_len);

/* Build absolute URL from relative path */
int url_resolve(const char *base, const char *relative, char *out, int out_len);

/* Free response body */
void http_response_free(http_response_t *resp);

/* Get HTTP method string */
const char *http_method_str(http_method_t method);

/* ============================================================
 * RECON ENGINE (recon.c)
 * ============================================================ */

/* Run reconnaissance phase */
int recon_run(scan_context_t *ctx);

/* Parse HTML for endpoints */
int recon_parse_html(const char *html, const char *base_url, endpoint_t *eps, int *count);

/* Parse JavaScript for API endpoints */
int recon_parse_js(const char *js_content, const char *base_url, endpoint_t *eps, int *count);

/* Parse robots.txt */
int recon_parse_robots(const char *robots_txt, endpoint_t *eps, int *count);

/* Parse sitemap.xml */
int recon_parse_sitemap(const char *sitemap, endpoint_t *eps, int *count);

/* GraphQL introspection probe */
int recon_graphql_probe(const char *base_url, endpoint_t *eps, int *count);

/* API path probing */
int recon_api_probe(const char *base_url, endpoint_t *eps, int *count);

/* ============================================================
 * AUTH BYPASS ENGINE (auth.c)
 * ============================================================ */

/* Run authentication bypass tests */
int auth_run(scan_context_t *ctx);

/* Test JWT algorithm confusion */
int auth_jwt_none(const char *token, const char *target_url, scan_context_t *ctx);

/* Test JWT key confusion (RS256→HS256) */
int auth_jwt_key_confusion(const char *token, const char *target_url, scan_context_t *ctx);

/* Brute-force JWT weak secrets */
int auth_jwt_bruteforce(const char *token, const char *target_url, scan_context_t *ctx);

/* Test header-based auth bypass */
int auth_header_bypass(const endpoint_t *ep, scan_context_t *ctx);

/* Test path-based auth bypass */
int auth_path_bypass(const endpoint_t *ep, scan_context_t *ctx);

/* Test HTTP method auth bypass */
int auth_method_bypass(const endpoint_t *ep, scan_context_t *ctx);

/* Test parameter pollution */
int auth_param_pollution(const endpoint_t *ep, scan_context_t *ctx);

/* ============================================================
 * RACE CONDITION ENGINE (race.c)
 * ============================================================ */

/* Run race condition tests */
int race_run(scan_context_t *ctx);

/* Test double-execution */
int race_double_exec(const endpoint_t *ep, scan_context_t *ctx);

/* Test token reuse (OTP, coupon, balance) */
int race_token_reuse(const endpoint_t *ep, scan_context_t *ctx);

/* Test concurrent state changes */
int race_state_change(const endpoint_t *ep, scan_context_t *ctx);

/* Measure timing distribution */
int race_measure_timing(const char *url, http_method_t method, 
                        const char *headers, const char *body,
                        timing_sample_t *sample, int num_requests);

/* Detect timing anomaly (TOCTOU) */
bool race_detect_anomaly(timing_sample_t *sample);

/* ============================================================
 * SSRF ENGINE (ssrf.c)
 * ============================================================ */

/* Run SSRF tests */
int ssrf_run(scan_context_t *ctx);

/* Test basic SSRF via parameter injection */
int ssrf_basic(const endpoint_t *ep, scan_context_t *ctx);

/* Test SSRF via redirect */
int ssrf_redirect(const endpoint_t *ep, scan_context_t *ctx);

/* Test SSRF to cloud metadata */
int ssrf_cloud_metadata(const endpoint_t *ep, scan_context_t *ctx);

/* Test SSRF with protocol smuggling */
int ssrf_proto_smuggle(const endpoint_t *ep, scan_context_t *ctx);

/* Test internal port scanning via SSRF */
int ssrf_internal_scan(const endpoint_t *ep, scan_context_t *ctx);

/* Analyze response for SSRF indicators */
bool ssrf_analyze_response(const http_response_t *resp, const char *indicator);

/* ============================================================
 * MASS ASSIGNMENT ENGINE (mass.c)
 * ============================================================ */

/* Run mass assignment tests */
int mass_run(scan_context_t *ctx);

/* Test hidden parameter discovery */
int mass_hidden_params(const endpoint_t *ep, scan_context_t *ctx);

/* Test content-type switching */
int mass_content_type(const endpoint_t *ep, scan_context_t *ctx);

/* Test HTTP method switching */
int mass_method_switch(const endpoint_t *ep, scan_context_t *ctx);

/* Diff responses for hidden fields */
bool mass_diff_response(const http_response_t *baseline, const http_response_t *modified);

/* ============================================================
 * HTTP SMUGGLING ENGINE (smuggle.c)
 * ============================================================ */

/* Run HTTP smuggling tests */
int smuggle_run(scan_context_t *ctx);

/* Test CL.TE smuggling */
int smuggle_clte(const endpoint_t *ep, scan_context_t *ctx);

/* Test TE.CL smuggling */
int smuggle_tecl(const endpoint_t *ep, scan_context_t *ctx);

/* Test TE.TE obfuscation */
int smuggle_tete(const endpoint_t *ep, scan_context_t *ctx);

/* Send raw HTTP request (for smuggling) */
int smuggle_raw_send(const char *host, int port, bool ssl, 
                     const char *payload, int payload_len,
                     char *response, int resp_len);

/* ============================================================
 * BUSINESS LOGIC ENGINE (logic.c)
 * ============================================================ */

/* Run business logic tests */
int logic_run(scan_context_t *ctx);

/* Test negative value injection */
int logic_negative(const endpoint_t *ep, scan_context_t *ctx);

/* Test integer overflow */
int logic_overflow(const endpoint_t *ep, scan_context_t *ctx);

/* Test type confusion */
int logic_type_confusion(const endpoint_t *ep, scan_context_t *ctx);

/* Test rate limit bypass */
int logic_rate_bypass(const endpoint_t *ep, scan_context_t *ctx);

/* Test state machine bypass */
int logic_state_bypass(const endpoint_t *ep, scan_context_t *ctx);

/* ============================================================
 * CRYPTO ANALYSIS ENGINE (crypto.c)
 * ============================================================ */

/* Run cryptographic analysis */
int crypto_run(scan_context_t *ctx);

/* Detect ECB mode in encrypted cookies/values */
int crypto_detect_ecb(const endpoint_t *ep, scan_context_t *ctx);

/* Detect weak hashing algorithms */
int crypto_weak_hash(const endpoint_t *ep, scan_context_t *ctx);

/* Timing side-channel analysis */
int crypto_timing_attack(const endpoint_t *ep, scan_context_t *ctx);

/* TLS configuration analysis */
int crypto_tls_analysis(const endpoint_t *ep, scan_context_t *ctx);

/* Detect padding oracle */
int crypto_padding_oracle(const endpoint_t *ep, scan_context_t *ctx);

/* ============================================================
 * VULNERABILITY CHAIN ANALYZER (chain.c)
 * ============================================================ */

/* Analyze findings for exploitable chains */
int chain_analyze(scan_context_t *ctx);

/* Check if two findings can be chained */
bool chain_compatible(const finding_t *a, const finding_t *b);

/* ============================================================
 * UTILITY FUNCTIONS (util.c)
 * ============================================================ */

/* Base64 encode/decode */
int base64_encode(const unsigned char *data, int len, char *out, int out_len);
int base64_decode(const char *data, unsigned char *out, int out_len);
int base64_url_encode(const unsigned char *data, int len, char *out, int out_len);
int base64_url_decode(const char *data, unsigned char *out, int out_len);

/* URL encode/decode */
int url_encode(const char *str, char *out, int out_len);
int url_decode(const char *str, char *out, int out_len);

/* JSON helpers */
char *json_get_value(const char *json, const char *key, char *val, int val_len);
bool json_has_key(const char *json, const char *key);

/* String helpers */
bool str_contains(const char *haystack, const char *needle);
bool str_contains_ci(const char *haystack, const char *needle);
char *str_skip_whitespace(char *s);
int str_count_char(const char *str, char c);

/* Hashing */
bool md5_hash(const char *data, char *out, int out_len);
bool sha1_hash(const char *data, char *out, int out_len);
bool sha256_hash(const char *data, char *out, int out_len);
bool hmac_sha256(const char *key, int key_len, const char *data, int data_len, char *out, int out_len);

/* Timing */
double time_now(void);
double time_diff_ms(double start, double end);

/* Logging */
void log_info(const char *fmt, ...);
void log_warning(const char *fmt, ...);
void log_error(const char *fmt, ...);
void log_verbose(const char *fmt, ...);
void log_set_level(int level);
int log_get_level(void);

/* Severity helpers */
const char *severity_str(severity_t sev);
const char *severity_color(severity_t sev);
const char *finding_type_str(finding_type_t type);

/* Thread pool */
typedef void *(*thread_func_t)(void *);

typedef struct {
    pthread_t threads[OMEGA_MAX_THREADS];
    int thread_count;
    bool running;
} thread_pool_t;

int thread_pool_init(thread_pool_t *pool, int count);
int thread_pool_submit(thread_pool_t *pool, thread_func_t func, void *arg);
void thread_pool_wait(thread_pool_t *pool);
void thread_pool_destroy(thread_pool_t *pool);

#endif /* OMEGA_H */
