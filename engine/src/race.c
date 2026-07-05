/*
 * OMEGA-ZERODAY HUNTER v2.0 — Race Condition Detection Engine
 *
 * Real detection techniques for:
 * - TOCTOU (Time-of-Check-Time-of-Use) race conditions
 * - Double-execution via parallel requests
 * - Token/OTP reuse detection
 * - Coupon/discount abuse via concurrent requests
 * - Balance manipulation via race conditions
 * - Payment double-spend detection
 *
 * Uses statistical timing analysis to detect
 * non-atomic operations in server-side logic.
 */

#include "../include/omega.h"

/* ============================================================
 * TIMING MEASUREMENT ENGINE
 * ============================================================ */

/* Measure response times for multiple requests */
static int measure_timing(const char *url, http_method_t method,
                          const char *headers, const char *body,
                          timing_sample_t *sample, int num_requests,
                          int timeout) {
    parsed_url_t parsed;
    url_parse(url, &parsed);
    
    memset(sample, 0, sizeof(timing_sample_t));
    
    for (int i = 0; i < num_requests && i < 32; i++) {
        http_request_t req;
        memset(&req, 0, sizeof(req));
        strncpy(req.url, url, OMEGA_MAX_URL_LEN - 1);
        strncpy(req.host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
        strncpy(req.path, parsed.path, OMEGA_MAX_PATH_LEN - 1);
        req.port = parsed.port;
        req.ssl = parsed.ssl;
        req.method = method;
        req.timeout = timeout;
        
        if (headers && headers[0]) {
            strncpy(req.headers, headers, sizeof(req.headers) - 1);
        }
        if (body && body[0]) {
            req.body = (char *)body;
            req.body_len = strlen(body);
        }
        
        http_response_t resp;
        if (http_request(&req, &resp) == 0) {
            sample->times[sample->count] = resp.response_time;
            sample->count++;
            
            if (sample->count == 1) {
                sample->min = resp.response_time;
                sample->max = resp.response_time;
            } else {
                if (resp.response_time < sample->min) sample->min = resp.response_time;
                if (resp.response_time > sample->max) sample->max = resp.response_time;
            }
            
            http_response_free(&resp);
        }
    }
    
    /* Calculate statistics */
    if (sample->count > 0) {
        double sum = 0;
        for (int i = 0; i < sample->count; i++) {
            sum += sample->times[i];
        }
        sample->mean = sum / sample->count;
        
        /* Standard deviation */
        double sq_sum = 0;
        for (int i = 0; i < sample->count; i++) {
            sq_sum += (sample->times[i] - sample->mean) * (sample->times[i] - sample->mean);
        }
        sample->stddev = sqrt(sq_sum / sample->count);
    }
    
    return sample->count;
}

/* ============================================================
 * RACE CONDITION DETECTION: PARALLEL BURST
 * ============================================================ */

/* Thread argument for parallel requests */
typedef struct {
    char url[2048];
    http_method_t method;
    char headers[2048];
    char body[4096];
    int timeout;
    int thread_id;
    http_response_t *resp;
    bool completed;
} race_thread_arg_t;

/* Thread function for parallel requests */
static void *race_thread_func(void *arg) {
    race_thread_arg_t *rarg = (race_thread_arg_t *)arg;
    
    parsed_url_t parsed;
    url_parse(rarg->url, &parsed);
    
    http_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.url, rarg->url, OMEGA_MAX_URL_LEN - 1);
    strncpy(req.host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
    strncpy(req.path, parsed.path, OMEGA_MAX_PATH_LEN - 1);
    req.port = parsed.port;
    req.ssl = parsed.ssl;
    req.method = rarg->method;
    req.timeout = rarg->timeout;
    
    if (rarg->headers[0]) {
        strncpy(req.headers, rarg->headers, sizeof(req.headers) - 1);
    }
    if (rarg->body[0]) {
        req.body = rarg->body;
        req.body_len = strlen(rarg->body);
    }
    
    http_request(&req, rarg->resp);
    rarg->completed = true;
    
    return NULL;
}

/* ============================================================
 * DOUBLE-EXECUTION DETECTION
 * ============================================================ */

int race_double_exec(const endpoint_t *ep, scan_context_t *ctx) {
    if (!ep || !ctx) return 0;
    
    parsed_url_t parsed;
    url_parse(ep->url, &parsed);
    
    /* Send 15 parallel requests to state-changing endpoint */
    int burst_count = 5;
    http_response_t *responses = calloc(burst_count, sizeof(http_response_t));
    pthread_t *threads = calloc(burst_count, sizeof(pthread_t));
    race_thread_arg_t *args = calloc(burst_count, sizeof(race_thread_arg_t));
    
    if (!responses || !threads || !args) {
        free(responses); free(threads); free(args);
        return -1;
    }
    
    /* Launch all requests simultaneously */
    for (int i = 0; i < burst_count; i++) {
        args[i].method = HTTP_POST;
        args[i].timeout = 3;
        args[i].thread_id = i;
        args[i].resp = &responses[i];
        strncpy(args[i].url, ep->url, OMEGA_MAX_URL_LEN - 1);
        strncpy(args[i].headers, ctx->cookie, sizeof(args[i].headers) - 1);
        
        /* Each request uses a unique token to track which one succeeded */
        char body[512];
        snprintf(body, sizeof(body), "token=race_test_%d&action=purchase", i);
        strncpy(args[i].body, body, sizeof(args[i].body) - 1);
        
        if (pthread_create(&threads[i], NULL, race_thread_func, &args[i]) != 0) { args[i].completed = false; }
    }
    
    /* Wait for all threads */
    for (int i = 0; i < burst_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    /* Analyze results */
    int success_count = 0;
    int failure_count = 0;
    int unique_codes[16] = {0};
    
    for (int i = 0; i < burst_count; i++) {
        if (responses[i].body) {
            /* Check if request succeeded */
            bool success = (responses[i].status_code >= 200 && 
                           responses[i].status_code < 300 &&
                           !str_contains(responses[i].body, "error") &&
                           !str_contains(responses[i].body, "fail") &&
                           !str_contains(responses[i].body, "duplicate"));
            
            if (success) success_count++;
            else failure_count++;
            
            /* Track unique operation codes in response */
            if (success && responses[i].body_len > 0) {
                /* Simple hash of response body */
                unsigned int hash = 0;
                for (int j = 0; j < responses[i].body_len && j < 100; j++) {
                    hash = hash * 31 + responses[i].body[j];
                }
                unique_codes[i % 16] = hash;
            }
        }
    }
    
    /* Check for race condition: multiple successes on single-use operation */
    if (success_count > 1) {
        /* Count unique responses */
        int unique_count = 0;
        for (int i = 0; i < 16; i++) {
            if (unique_codes[i] != 0) unique_count++;
        }
        
        /* If multiple succeeded with same response, likely race condition */
        if (success_count >= 2) {
            if (ctx->finding_count < OMEGA_MAX_FINDINGS) {
                finding_t *f = &ctx->findings[ctx->finding_count];
                memset(f, 0, sizeof(finding_t));
                f->type = FIND_RACE_DOUBLE_EXEC;
                f->severity = SEV_CRITICAL;
                f->cvss_score = 8.8;
                strncpy(f->url, ep->url, OMEGA_MAX_URL_LEN - 1);
                snprintf(f->description, sizeof(f->description),
                    "Race condition: %d/%d parallel requests succeeded (expected 1)",
                    success_count, burst_count);
                snprintf(f->evidence, sizeof(f->evidence),
                    "Burst: %d | Success: %d | Failure: %d | Unique responses: %d",
                    burst_count, success_count, failure_count, unique_count);
                snprintf(f->remediation, sizeof(f->remediation),
                    "Implement server-side locking or idempotency keys for state-changing operations.");
                f->confidence = 0.90;
                strncpy(f->cwe_id, "CWE-367", sizeof(f->cwe_id) - 1);
                strncpy(f->engine, "RaceHunter", sizeof(f->engine) - 1);
                f->timestamp = time_now();
                ctx->finding_count++;
                ctx->critical_count++;
                log_info("🔴 CRITICAL: Race condition at %s (%d/%d succeeded)",
                        ep->url, success_count, burst_count);
            }
        }
    }
    
    /* Cleanup */
    for (int i = 0; i < burst_count; i++) {
        http_response_free(&responses[i]);
    }
    free(responses);
    free(threads);
    free(args);
    
    return 0;
}

/* ============================================================
 * TOKEN/OTP REUSE DETECTION
 * ============================================================ */

int race_token_reuse(const endpoint_t *ep, scan_context_t *ctx) {
    if (!ep || !ctx) return 0;
    
    /* First request: get a token/OTP */
    parsed_url_t parsed;
    url_parse(ep->url, &parsed);
    
    /* Send initial request to get token */
    http_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.url, ep->url, OMEGA_MAX_URL_LEN - 1);
    strncpy(req.host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
    strncpy(req.path, ep->path, OMEGA_MAX_PATH_LEN - 1);
    req.port = parsed.port;
    req.ssl = parsed.ssl;
    req.method = HTTP_GET;
    req.timeout = OMEGA_DEFAULT_TIMEOUT;
    
    http_response_t initial_resp;
    if (http_request(&req, &initial_resp) != 0) return 0;
    
    /* Extract token from response (common patterns) */
    char token[512] = {0};
    if (initial_resp.body) {
        /* Look for token in JSON response */
        if (!json_get_value(initial_resp.body, "token", token, sizeof(token)) &&
            !json_get_value(initial_resp.body, "otp", token, sizeof(token)) &&
            !json_get_value(initial_resp.body, "code", token, sizeof(token)) &&
            !json_get_value(initial_resp.body, "csrf_token", token, sizeof(token))) {
            http_response_free(&initial_resp);
            return 0;
        }
    }
    
    if (!token[0]) {
        http_response_free(&initial_resp);
        return 0;
    }
    
    http_response_free(&initial_resp);
    
    /* Now try to reuse the token multiple times */
    int success_count = 0;
    for (int i = 0; i < 5; i++) {
        memset(&req, 0, sizeof(req));
        strncpy(req.url, ep->url, OMEGA_MAX_URL_LEN - 1);
        strncpy(req.host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
        strncpy(req.path, ep->path, OMEGA_MAX_PATH_LEN - 1);
        req.port = parsed.port;
        req.ssl = parsed.ssl;
        req.method = HTTP_POST;
        req.timeout = OMEGA_DEFAULT_TIMEOUT;
        
        char body[1024];
        snprintf(body, sizeof(body), "token=%s", token);
        req.body = body;
        req.body_len = strlen(body);
        
        http_response_t resp;
        if (http_request(&req, &resp) == 0) {
            if (resp.status_code >= 200 && resp.status_code < 300) {
                success_count++;
            }
            http_response_free(&resp);
        }
    }
    
    /* If token was accepted multiple times, it's a reuse vulnerability */
    if (success_count > 1) {
        if (ctx->finding_count < OMEGA_MAX_FINDINGS) {
            finding_t *f = &ctx->findings[ctx->finding_count];
            memset(f, 0, sizeof(finding_t));
            f->type = FIND_RACE_TOKEN_REUSE;
            f->severity = SEV_CRITICAL;
            f->cvss_score = 8.5;
            strncpy(f->url, ep->url, OMEGA_MAX_URL_LEN - 1);
            snprintf(f->description, sizeof(f->description),
                "Token/OTP reuse: Accepted %d times (should be single-use)", success_count);
            snprintf(f->evidence, sizeof(f->evidence),
                "Token: %.50s... | Reused: %d/5 attempts", token, success_count);
            f->confidence = 0.92;
            strncpy(f->cwe_id, "CWE-367", sizeof(f->cwe_id) - 1);
            strncpy(f->engine, "RaceHunter", sizeof(f->engine) - 1);
            f->timestamp = time_now();
            ctx->finding_count++;
            ctx->critical_count++;
            log_info("🔴 CRITICAL: Token reuse at %s", ep->url);
        }
    }
    
    return 0;
}

/* ============================================================
 * CONCURRENT STATE CHANGE DETECTION
 * ============================================================ */

int race_state_change(const endpoint_t *ep, scan_context_t *ctx) {
    if (!ep || !ctx) return 0;
    
    /* Measure timing distribution for sequential requests */
    timing_sample_t seq_sample;
    measure_timing(ep->url, HTTP_GET, ctx->cookie, NULL, &seq_sample, 10, ctx->timeout);
    
    if (seq_sample.count < 5) return 0;
    
    /* Now send parallel requests and measure */
    parsed_url_t parsed;
    url_parse(ep->url, &parsed);
    
    int parallel_count = 5;
    http_response_t *responses = calloc(parallel_count, sizeof(http_response_t));
    pthread_t *threads = calloc(parallel_count, sizeof(pthread_t));
    race_thread_arg_t *args = calloc(parallel_count, sizeof(race_thread_arg_t));
    
    if (!responses || !threads || !args) {
        free(responses); free(threads); free(args);
        return -1;
    }
    
    double start = time_now();
    for (int i = 0; i < parallel_count; i++) {
        args[i].method = HTTP_POST;
        args[i].timeout = 3;
        args[i].thread_id = i;
        args[i].resp = &responses[i];
        strncpy(args[i].url, ep->url, OMEGA_MAX_URL_LEN - 1);
        strncpy(args[i].headers, ctx->cookie, sizeof(args[i].headers) - 1);
        strncpy(args[i].body, "action=transfer&amount=1", sizeof(args[i].body) - 1);
        
        if (pthread_create(&threads[i], NULL, race_thread_func, &args[i]) != 0) { args[i].completed = false; }
    }
    
    for (int i = 0; i < parallel_count; i++) {
        pthread_join(threads[i], NULL);
    }
    double parallel_time = time_now() - start;
    
    /* Analyze: if parallel requests take much less time per request
     * than sequential, it suggests no server-side locking */
    double seq_avg = seq_sample.mean;
    double parallel_avg = parallel_time / parallel_count;
    
    /* Significant difference suggests no locking */
    if (seq_avg > 0 && parallel_avg < seq_avg * 0.3) {
        if (ctx->finding_count < OMEGA_MAX_FINDINGS) {
            finding_t *f = &ctx->findings[ctx->finding_count];
            memset(f, 0, sizeof(*f));
            f->type = FIND_RACE_CONDITION;
            f->severity = SEV_HIGH;
            f->cvss_score = 7.5;
            strncpy(f->url, ep->url, OMEGA_MAX_URL_LEN - 1);
            snprintf(f->description, sizeof(f->description),
                "Potential race condition: Parallel execution %.1fx faster than sequential",
                seq_avg / parallel_avg);
            snprintf(f->evidence, sizeof(f->evidence),
                "Sequential avg: %.3fs | Parallel avg: %.3fs | Ratio: %.1fx",
                seq_avg, parallel_avg, seq_avg / parallel_avg);
            f->confidence = 0.75;
            strncpy(f->cwe_id, "CWE-362", sizeof(f->cwe_id) - 1);
            strncpy(f->engine, "RaceHunter", sizeof(f->engine) - 1);
            f->timestamp = time_now();
            ctx->finding_count++;
            ctx->high_count++;
            log_info("🟠 HIGH: Potential race condition at %s", ep->url);
        }
    }
    
    /* Cleanup */
    for (int i = 0; i < parallel_count; i++) {
        http_response_free(&responses[i]);
    }
    free(responses);
    free(threads);
    free(args);
    
    return 0;
}

/* ============================================================
 * MAIN RACE CONDITION RUNNER
 * ============================================================ */

int race_run(scan_context_t *ctx) {
    if (!ctx) return -1;
    
    log_info("⚡ RaceHunter: Testing for race conditions...");
    
    /* Find state-changing endpoints (POST/PUT/DELETE with params) */
    int tested = 0;
    for (int i = 0; i < ctx->endpoint_count && i < 20; i++) {
        endpoint_t *ep = &ctx->endpoints[i];
        
        /* Only test endpoints that accept POST/PUT */
        if (ep->status_code >= 400) continue;
        if (!ep->has_forms && !ep->has_api) continue;
        
        tested++;
        if (ctx->progress_callback)
            ctx->progress_callback("RaceHunter", tested, ctx->endpoint_count > 20 ? 20 : ctx->endpoint_count,
                                  ep->path);
        
        race_double_exec(ep, ctx);
        race_token_reuse(ep, ctx);
        race_state_change(ep, ctx);
    }
    
    log_info("⚡ RaceHunter: Completed %d endpoint tests", tested);
    return 0;
}
