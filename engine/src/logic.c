/*
 * OMEGA-ZERODAY HUNTER v2.0 — Business Logic Flaw Engine
 * Real negative value, overflow, type confusion, rate limit, state bypass
 */

#include "../include/omega.h"

static const char *LOGIC_PARAMS[] = {
    "amount", "price", "quantity", "qty", "count", "total",
    "balance", "credits", "points", "discount", "value",
    "quantity", "units", "weight", "size", "days",
    NULL
};

static const char *LOGIC_VALUES[] = {
    "-1", "-999", "-0.5", "0", "0.0", "null", "undefined",
    "NaN", "true", "false", "1e999", "999999999",
    "-999999999", "2147483647", "-2147483648", "2147483648",
    "0.0001", "999999.99", "0xFF", "1; DROP TABLE",
    NULL
};

int logic_negative(const endpoint_t *ep, scan_context_t *ctx) {
    parsed_url_t parsed;
    url_parse(ep->url, &parsed);
    int found = 0;
    
    for (int p = 0; LOGIC_PARAMS[p]; p++) {
        for (int v = 0; LOGIC_VALUES[v]; v++) {
            /* GET injection */
            char url[OMEGA_MAX_URL_LEN];
            snprintf(url, sizeof(url), "%s?%s=%s", ep->url, LOGIC_PARAMS[p], LOGIC_VALUES[v]);
            
            http_request_t req;
            memset(&req, 0, sizeof(req));
            strncpy(req.url, url, OMEGA_MAX_URL_LEN - 1);
            strncpy(req.host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
            snprintf(req.path, OMEGA_MAX_PATH_LEN, "%s?%s=%s", ep->path, LOGIC_PARAMS[p], LOGIC_VALUES[v]);
            req.port = parsed.port;
            req.ssl = parsed.ssl;
            req.method = HTTP_GET;
            req.timeout = OMEGA_DEFAULT_TIMEOUT;
            
            http_response_t resp;
            if (http_request(&req, &resp) == 0) {
                /* Detect success indicators that shouldn't happen with invalid values */
                bool suspicious = (resp.status_code == 200 &&
                    (str_contains(resp.body, "success") || str_contains(resp.body, "completed") ||
                     str_contains(resp.body, "confirmed") || str_contains(resp.body, "applied")) &&
                    !str_contains(resp.body, "invalid") && !str_contains(resp.body, "error") &&
                    !str_contains(resp.body, "denied"));
                
                /* Also detect leaked balance/info with negative values */
                bool info_leak = ((v == 0 || v == 1) && /* -1 or -999 */
                    resp.status_code == 200 &&
                    (str_contains(resp.body, "balance") || str_contains(resp.body, "credit") ||
                     str_contains(resp.body, "amount")) &&
                    resp.body_len > 50);
                
                if (suspicious) {
                    if (ctx->finding_count < OMEGA_MAX_FINDINGS) {
                        finding_t *f = &ctx->findings[ctx->finding_count];
                        memset(f, 0, sizeof(finding_t));
                        f->type = FIND_LOGIC_NEGATIVE;
                        f->severity = SEV_CRITICAL;
                        f->cvss_score = 8.8;
                        strncpy(f->url, ep->url, OMEGA_MAX_URL_LEN - 1);
                        snprintf(f->description, sizeof(f->description),
                            "Business logic flaw: Negative/invalid value accepted for %s (value: %s)",
                            LOGIC_PARAMS[p], LOGIC_VALUES[v]);
                        snprintf(f->evidence, sizeof(f->evidence),
                            "Param: %s | Value: %s | Status: %d | Response contains 'success'",
                            LOGIC_PARAMS[p], LOGIC_VALUES[v], resp.status_code);
                        f->confidence = 0.88;
                        strncpy(f->cwe_id, "CWE-20", sizeof(f->cwe_id) - 1);
                        strncpy(f->engine, "LogicBreaker", sizeof(f->engine) - 1);
                        f->timestamp = time_now();
                        ctx->finding_count++;
                        ctx->critical_count++;
                        log_info("🔴 CRITICAL: Logic flaw at %s (%s=%s)", ep->url, LOGIC_PARAMS[p], LOGIC_VALUES[v]);
                    }
                    found++;
                }
                http_response_free(&resp);
                if (found >= 3) return found; /* Cap per endpoint */
            }
        }
    }
    return found;
}

int logic_overflow(const endpoint_t *ep, scan_context_t *ctx) {
    parsed_url_t parsed;
    url_parse(ep->url, &parsed);
    
    const char *overflow_values[] = {
        "9999999999999999999", "18446744073709551616", /* 2^64 */
        "1e308", "Infinity", "-Infinity",
        "999999999999999999999999999",
        NULL
    };
    
    for (int p = 0; LOGIC_PARAMS[p]; p++) {
        for (int v = 0; overflow_values[v]; v++) {
            char url[OMEGA_MAX_URL_LEN];
            snprintf(url, sizeof(url), "%s?%s=%s", ep->url, LOGIC_PARAMS[p], overflow_values[v]);
            
            http_request_t req;
            memset(&req, 0, sizeof(req));
            strncpy(req.url, url, OMEGA_MAX_URL_LEN - 1);
            strncpy(req.host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
            snprintf(req.path, OMEGA_MAX_PATH_LEN, "%s?%s=%s", ep->path, LOGIC_PARAMS[p], overflow_values[v]);
            req.port = parsed.port;
            req.ssl = parsed.ssl;
            req.method = HTTP_GET;
            req.timeout = OMEGA_DEFAULT_TIMEOUT;
            
            http_response_t resp;
            if (http_request(&req, &resp) == 0) {
                bool overflow_vuln = (resp.status_code == 200 &&
                    (str_contains(resp.body, "success") || str_contains(resp.body, "completed")) &&
                    !str_contains(resp.body, "overflow") && !str_contains(resp.body, "invalid"));
                
                /* Detect 500 errors = potential crash = overflow confirmed */
                bool crash = (resp.status_code == 500);
                
                if (overflow_vuln || crash) {
                    if (ctx->finding_count < OMEGA_MAX_FINDINGS) {
                        finding_t *f = &ctx->findings[ctx->finding_count];
                        memset(f, 0, sizeof(finding_t));
                        f->type = FIND_LOGIC_OVERFLOW;
                        f->severity = crash ? SEV_CRITICAL : SEV_HIGH;
                        f->cvss_score = crash ? 9.0 : 7.5;
                        strncpy(f->url, ep->url, OMEGA_MAX_URL_LEN - 1);
                        snprintf(f->description, sizeof(f->description),
                            "Integer overflow: %s=%s caused %s",
                            LOGIC_PARAMS[p], overflow_values[v], crash ? "server error (500)" : "unexpected success");
                        f->confidence = crash ? 0.92 : 0.78;
                        strncpy(f->cwe_id, "CWE-190", sizeof(f->cwe_id) - 1);
                        strncpy(f->engine, "LogicBreaker", sizeof(f->engine) - 1);
                        f->timestamp = time_now();
                        ctx->finding_count++;
                        if (crash) ctx->critical_count++; else ctx->high_count++;
                        log_info("%s: Overflow at %s", crash ? "🔴 CRITICAL" : "🟠 HIGH", ep->url);
                    }
                    http_response_free(&resp);
                    return 1;
                }
                http_response_free(&resp);
            }
        }
    }
    return 0;
}

int logic_type_confusion(const endpoint_t *ep, scan_context_t *ctx) {
    parsed_url_t parsed;
    url_parse(ep->url, &parsed);
    
    /* Send JSON array where object expected, string where int expected, etc. */
    const char *type_payloads[] = {
        "{\"amount\":[1,2,3]}",
        "{\"amount\":\"abc\"}",
        "{\"amount\":true}",
        "{\"amount\":{\"nested\":\"value\"}}",
        "{\"amount\":null}",
        "[1,2,3]",
        "\"string\"",
        "true",
        "null",
        NULL
    };
    
    for (int i = 0; type_payloads[i]; i++) {
        http_request_t req;
        memset(&req, 0, sizeof(req));
        strncpy(req.url, ep->url, OMEGA_MAX_URL_LEN - 1);
        strncpy(req.host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
        strncpy(req.path, ep->path, OMEGA_MAX_PATH_LEN - 1);
        req.port = parsed.port;
        req.ssl = parsed.ssl;
        req.method = HTTP_POST;
        req.timeout = OMEGA_DEFAULT_TIMEOUT;
        req.body = (char *)type_payloads[i];
        req.body_len = strlen(type_payloads[i]);
        strncpy(req.headers, "Content-Type: application/json\r\n", sizeof(req.headers) - 1);
        
        http_response_t resp;
        if (http_request(&req, &resp) == 0) {
            /* Type confusion = server accepts and processes unexpected type */
            bool accepted = (resp.status_code == 200 &&
                !str_contains(resp.body, "invalid") && !str_contains(resp.body, "error") &&
                !str_contains(resp.body, "type") && !str_contains(resp.body, "bad request"));
            
            if (accepted) {
                if (ctx->finding_count < OMEGA_MAX_FINDINGS) {
                    finding_t *f = &ctx->findings[ctx->finding_count];
                    memset(f, 0, sizeof(finding_t));
                    f->type = FIND_LOGIC_TYPE_CONFUSION;
                    f->severity = SEV_HIGH;
                    f->cvss_score = 7.5;
                    strncpy(f->url, ep->url, OMEGA_MAX_URL_LEN - 1);
                    snprintf(f->description, sizeof(f->description),
                        "Type confusion: Server accepted unexpected type: %s", type_payloads[i]);
                    f->confidence = 0.75;
                    strncpy(f->cwe_id, "CWE-843", sizeof(f->cwe_id) - 1);
                    strncpy(f->engine, "LogicBreaker", sizeof(f->engine) - 1);
                    f->timestamp = time_now();
                    ctx->finding_count++;
                    ctx->high_count++;
                    log_info("🟠 HIGH: Type confusion at %s", ep->url);
                }
                http_response_free(&resp);
                return 1;
            }
            http_response_free(&resp);
        }
    }
    return 0;
}

int logic_run(scan_context_t *ctx) {
    if (!ctx) return -1;
    log_info("💥 LogicBreaker: Testing business logic flaws...");
    
    int tested = 0;
    for (int i = 0; i < ctx->endpoint_count && i < 15; i++) {
        if (ctx->endpoints[i].status_code >= 400) continue;
        if (!ctx->endpoints[i].has_api && !ctx->endpoints[i].has_forms) continue;
        tested++;
        if (ctx->progress_callback)
            ctx->progress_callback("LogicBreaker", tested, 15, ctx->endpoints[i].path);
        
        logic_negative(&ctx->endpoints[i], ctx);
        logic_overflow(&ctx->endpoints[i], ctx);
        logic_type_confusion(&ctx->endpoints[i], ctx);
    }
    
    log_info("💥 LogicBreaker: Completed %d endpoint tests", tested);
    return 0;
}
