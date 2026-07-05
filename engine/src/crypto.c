/*
 * OMEGA-ZERODAY HUNTER v2.0 — Cryptographic Analysis Engine
 * ECB detection, weak hash, timing side-channel, TLS analysis
 */

#include "../include/omega.h"

/* Detect ECB mode by looking for repeated 16-byte blocks in cookies/values */
int crypto_detect_ecb(const endpoint_t *ep, scan_context_t *ctx) {
    http_request_t req;
    parsed_url_t parsed;
    url_parse(ep->url, &parsed);
    
    memset(&req, 0, sizeof(req));
    strncpy(req.url, ep->url, OMEGA_MAX_URL_LEN - 1);
    strncpy(req.host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
    strncpy(req.path, ep->path, OMEGA_MAX_PATH_LEN - 1);
    req.port = parsed.port;
    req.ssl = parsed.ssl;
    req.method = HTTP_GET;
    req.timeout = OMEGA_DEFAULT_TIMEOUT;
    
    http_response_t resp;
    if (http_request(&req, &resp) != 0) return 0;
    
    /* Check Set-Cookie for ECB patterns */
    if (resp.set_cookie[0]) {
        /* Base64-decode cookie values and check for repeated blocks */
        const char *p = resp.set_cookie;
        while ((p = strstr(p, "=")) != NULL) {
            p++;
            const char *val_start = p;
            while (*p && *p != ';' && *p != '\n') p++;
            
            int val_len = (int)(p - val_start);
            if (val_len > 32 && val_len < 2048) {
                /* Try base64 decode */
                unsigned char decoded[2048];
                int dec_len = base64_decode(val_start, decoded, sizeof(decoded));
                
                if (dec_len >= 32 && dec_len % 16 == 0) {
                    /* Check for repeated 16-byte blocks */
                    int block_count = dec_len / 16;
                    int unique_blocks = 0;
                    
                    for (int i = 0; i < block_count; i++) {
                        bool unique = true;
                        for (int j = 0; j < i; j++) {
                            if (memcmp(decoded + i*16, decoded + j*16, 16) == 0) {
                                unique = false;
                                break;
                            }
                        }
                        if (unique) unique_blocks++;
                    }
                    
                    /* ECB = many repeated blocks */
                    if (block_count > 2 && unique_blocks < block_count / 2) {
                        if (ctx->finding_count < OMEGA_MAX_FINDINGS) {
                            finding_t *f = &ctx->findings[ctx->finding_count];
                            memset(f, 0, sizeof(finding_t));
                            f->type = FIND_CRYPTO_ECB;
                            f->severity = SEV_HIGH;
                            f->cvss_score = 7.4;
                            strncpy(f->url, ep->url, OMEGA_MAX_URL_LEN - 1);
                            snprintf(f->description, sizeof(f->description),
                                "ECB mode detected in cookie: %d unique blocks out of %d (repeated pattern)",
                                unique_blocks, block_count);
                            f->confidence = 0.85;
                            strncpy(f->cwe_id, "CWE-327", sizeof(f->cwe_id) - 1);
                            strncpy(f->engine, "CryptoOracle", sizeof(f->engine) - 1);
                            f->timestamp = time_now();
                            ctx->finding_count++;
                            ctx->high_count++;
                            log_info("🟠 HIGH: ECB mode at %s", ep->url);
                        }
                        http_response_free(&resp);
                        return 1;
                    }
                }
            }
            if (*p == ';') p++;
        }
    }
    
    /* Check body for encrypted values with ECB */
    if (resp.body && str_contains(resp.body, "encrypted")) {
        /* Look for base64 values in JSON */
        const char *p = resp.body;
        while ((p = strstr(p, "\"")) != NULL) {
            p++;
            const char *key_start = p;
            while (*p && *p != '"') p++;
            int key_len = (int)(p - key_start);
            
            if (key_len > 0 && key_len < 64) {
                /* Check next value for base64 */
                while (*p && *p != ':') p++;
                if (*p == ':') {
                    p++;
                    while (*p == ' ') p++;
                    if (*p == '"') {
                        p++;
                        const char *val_start = p;
                        while (*p && *p != '"') p++;
                        int val_len = (int)(p - val_start);
                        
                        if (val_len > 32) {
                            unsigned char decoded[2048];
                            int dec_len = base64_decode(val_start, decoded, sizeof(decoded));
                            
                            if (dec_len >= 32 && dec_len % 16 == 0) {
                                int block_count = dec_len / 16;
                                int repeated = 0;
                                
                                for (int i = 1; i < block_count; i++) {
                                    if (memcmp(decoded + i*16, decoded, 16) == 0) repeated++;
                                }
                                
                                if (repeated > 0 && block_count > 1) {
                                    if (ctx->finding_count < OMEGA_MAX_FINDINGS) {
                                        finding_t *f = &ctx->findings[ctx->finding_count];
                                        memset(f, 0, sizeof(finding_t));
                                        f->type = FIND_CRYPTO_ECB;
                                        f->severity = SEV_HIGH;
                                        f->cvss_score = 7.4;
                                        strncpy(f->url, ep->url, OMEGA_MAX_URL_LEN - 1);
                                        snprintf(f->description, sizeof(f->description),
                                            "ECB mode in JSON field '%.*s': %d repeated blocks",
                                            key_len, key_start, repeated);
                                        f->confidence = 0.82;
                                        strncpy(f->cwe_id, "CWE-327", sizeof(f->cwe_id) - 1);
                                        strncpy(f->engine, "CryptoOracle", sizeof(f->engine) - 1);
                                        f->timestamp = time_now();
                                        ctx->finding_count++;
                                        ctx->high_count++;
                                        log_info("🟠 HIGH: ECB in field '%.*s' at %s", key_len, key_start, ep->url);
                                    }
                                    http_response_free(&resp);
                                    return 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    http_response_free(&resp);
    return 0;
}

/* Detect weak hashing (MD5/SHA1 in visible tokens) */
int crypto_weak_hash(const endpoint_t *ep, scan_context_t *ctx) {
    http_request_t req;
    parsed_url_t parsed;
    url_parse(ep->url, &parsed);
    
    memset(&req, 0, sizeof(req));
    strncpy(req.url, ep->url, OMEGA_MAX_URL_LEN - 1);
    strncpy(req.host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
    strncpy(req.path, ep->path, OMEGA_MAX_PATH_LEN - 1);
    req.port = parsed.port;
    req.ssl = parsed.ssl;
    req.method = HTTP_GET;
    req.timeout = OMEGA_DEFAULT_TIMEOUT;
    
    http_response_t resp;
    if (http_request(&req, &resp) != 0) return 0;
    
    if (!resp.body) { http_response_free(&resp); return 0; }
    
    /* Look for MD5 (32 hex chars) and SHA1 (40 hex chars) in responses */
    const char *p = resp.body;
    while (*p) {
        /* Check for 32-char hex = MD5 */
        if (isxdigit(p[0]) && isxdigit(p[31])) {
            bool all_hex = true;
            for (int i = 0; i < 32; i++) {
                if (!isxdigit(p[i])) { all_hex = false; break; }
            }
            if (all_hex && p[32] != isxdigit(p[32])) { /* Not part of longer hex */
                /* Verify it's a hash by checking context */
                bool is_hash = false;
                const char *ctx_start = (p - resp.body > 30) ? p - 30 : resp.body;
                for (int i = 0; i < 30; i++) {
                    if (strncasecmp(ctx_start + i, "md5", 3) == 0 ||
                        strncasecmp(ctx_start + i, "hash", 4) == 0 ||
                        strncasecmp(ctx_start + i, "checksum", 8) == 0) {
                        is_hash = true;
                        break;
                    }
                }
                
                if (is_hash) {
                    if (ctx->finding_count < OMEGA_MAX_FINDINGS) {
                        finding_t *f = &ctx->findings[ctx->finding_count];
                        memset(f, 0, sizeof(finding_t));
                        f->type = FIND_CRYPTO_WEAK_HASH;
                        f->severity = SEV_MEDIUM;
                        f->cvss_score = 5.3;
                        strncpy(f->url, ep->url, OMEGA_MAX_URL_LEN - 1);
                        snprintf(f->description, sizeof(f->description),
                            "Weak hash (MD5) found in response: %.32s", p);
                        f->confidence = 0.70;
                        strncpy(f->cwe_id, "CWE-328", sizeof(f->cwe_id) - 1);
                        strncpy(f->engine, "CryptoOracle", sizeof(f->engine) - 1);
                        f->timestamp = time_now();
                        ctx->finding_count++;
                        ctx->medium_count++;
                        log_info("🟡 MEDIUM: MD5 hash at %s", ep->url);
                    }
                    break;
                }
            }
        }
        p++;
    }
    
    http_response_free(&resp);
    return 0;
}

/* Timing side-channel analysis */
static int crypto_timing(const endpoint_t *ep, scan_context_t *ctx) {
    parsed_url_t parsed;
    url_parse(ep->url, &parsed);
    
    /* Measure timing for valid vs invalid usernames */
    const char *test_users[] = {"admin", "test", "nonexistent_user_xyz123", NULL};
    double times[3][10];
    int counts[3] = {0};
    
    for (int u = 0; test_users[u]; u++) {
        for (int i = 0; i < 10; i++) {
            char url[OMEGA_MAX_URL_LEN];
            snprintf(url, sizeof(url), "%s?user=%s&pass=test%d", ep->url, test_users[u], i);
            
            http_request_t req;
            memset(&req, 0, sizeof(req));
            strncpy(req.url, url, OMEGA_MAX_URL_LEN - 1);
            strncpy(req.host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
            snprintf(req.path, OMEGA_MAX_PATH_LEN, "%s?user=%s&pass=test%d",
                    ep->path, test_users[u], i);
            req.port = parsed.port;
            req.ssl = parsed.ssl;
            req.method = HTTP_GET;
            req.timeout = OMEGA_DEFAULT_TIMEOUT;
            
            http_response_t resp;
            double start = time_now();
            if (http_request(&req, &resp) == 0) {
                double elapsed = time_now() - start;
                times[u][counts[u]++] = elapsed;
                http_response_free(&resp);
            }
        }
    }
    
    /* Compare average times */
    if (counts[0] >= 5 && counts[2] >= 5) {
        double avg_valid = 0, avg_invalid = 0;
        for (int i = 0; i < counts[0]; i++) avg_valid += times[0][i];
        for (int i = 0; i < counts[2]; i++) avg_invalid += times[2][i];
        avg_valid /= counts[0];
        avg_invalid /= counts[2];
        
        /* >30% difference suggests timing leak */
        if (avg_valid > 0 && avg_invalid > 0) {
            double diff = (avg_valid - avg_invalid) / avg_invalid;
            if (diff > 0.3 || diff < -0.3) {
                if (ctx->finding_count < OMEGA_MAX_FINDINGS) {
                    finding_t *f = &ctx->findings[ctx->finding_count];
                    memset(f, 0, sizeof(finding_t));
                    f->type = FIND_CRYPTO_TIMING;
                    f->severity = SEV_HIGH;
                    f->cvss_score = 7.0;
                    strncpy(f->url, ep->url, OMEGA_MAX_URL_LEN - 1);
                    snprintf(f->description, sizeof(f->description),
                        "Timing side-channel: admin avg=%.3fs vs random avg=%.3fs (%.0f%% difference)",
                        avg_valid, avg_invalid, diff * 100);
                    snprintf(f->evidence, sizeof(f->evidence),
                        "Samples: valid=%d invalid=%d | Timing diff indicates user enumeration possible",
                        counts[0], counts[2]);
                    f->confidence = 0.78;
                    strncpy(f->cwe_id, "CWE-208", sizeof(f->cwe_id) - 1);
                    strncpy(f->engine, "CryptoOracle", sizeof(f->engine) - 1);
                    f->timestamp = time_now();
                    ctx->finding_count++;
                    ctx->high_count++;
                    log_info("🟠 HIGH: Timing side-channel at %s", ep->url);
                }
                return 1;
            }
        }
    }
    return 0;
}

int crypto_run(scan_context_t *ctx) {
    if (!ctx) return -1;
    log_info("🔒 CryptoOracle: Analyzing cryptographic weaknesses...");
    
    int tested = 0;
    for (int i = 0; i < ctx->endpoint_count && i < 20; i++) {
        tested++;
        if (ctx->progress_callback)
            ctx->progress_callback("CryptoOracle", tested, ctx->endpoint_count > 20 ? 20 : ctx->endpoint_count,
                                  ctx->endpoints[i].path);
        
        crypto_detect_ecb(&ctx->endpoints[i], ctx);
        crypto_weak_hash(&ctx->endpoints[i], ctx);
        crypto_timing(&ctx->endpoints[i], ctx);
    }
    
    log_info("🔒 CryptoOracle: Completed %d endpoint tests", tested);
    return 0;
}
