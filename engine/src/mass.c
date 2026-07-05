/*
 * OMEGA-ZERODAY HUNTER v2.0 — Mass Assignment Engine
 * Hidden parameter discovery, content-type switching, method switching
 */

#include "../include/omega.h"

static const char *HIDDEN_PARAMS[] = {
    "admin", "is_admin", "role", "user_role", "privilege", "level",
    "verified", "is_verified", "email_verified", "approved",
    "balance", "credits", "points", "discount", "price", "amount",
    "user_id", "uid", "account_id", "owner_id", "created_by",
    "debug", "test", "internal", "developer", "superuser",
    "bypass", "override", "enabled", "active", "status",
    "type", "category", "permission", "access", "acl",
    NULL
};

int mass_hidden_params(const endpoint_t *ep, scan_context_t *ctx) {
    parsed_url_t parsed;
    url_parse(ep->url, &parsed);
    
    /* First get baseline response */
    http_request_t baseline_req;
    memset(&baseline_req, 0, sizeof(baseline_req));
    strncpy(baseline_req.url, ep->url, OMEGA_MAX_URL_LEN - 1);
    strncpy(baseline_req.host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
    strncpy(baseline_req.path, ep->path, OMEGA_MAX_PATH_LEN - 1);
    baseline_req.port = parsed.port;
    baseline_req.ssl = parsed.ssl;
    baseline_req.method = HTTP_POST;
    baseline_req.timeout = OMEGA_DEFAULT_TIMEOUT;
    baseline_req.body = "test=1";
    baseline_req.body_len = 6;
    strncpy(baseline_req.headers, "Content-Type: application/x-www-form-urlencoded\r\n",
            sizeof(baseline_req.headers) - 1);
    
    http_response_t baseline;
    if (http_request(&baseline_req, &baseline) != 0) return 0;
    
    /* Now inject hidden parameters one by one */
    for (int i = 0; HIDDEN_PARAMS[i]; i++) {
        char body[4096];
        snprintf(body, sizeof(body), "test=1&%s=1", HIDDEN_PARAMS[i]);
        
        http_request_t req;
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
        
        http_response_t resp;
        if (http_request(&req, &resp) == 0) {
            /* Detect hidden parameter: different response size/status */
            bool diff = (resp.status_code != baseline.status_code) ||
                       (abs(resp.body_len - baseline.body_len) > 50);
            
            /* Also detect by checking response content for parameter echo */
            bool param_reflected = str_contains(resp.body, HIDDEN_PARAMS[i]) ||
                                   str_contains(resp.body, "admin") ||
                                   str_contains(resp.body, "privilege") ||
                                   str_contains(resp.body, "role");
            
            if (diff || param_reflected) {
                if (ctx->finding_count < OMEGA_MAX_FINDINGS) {
                    finding_t *f = &ctx->findings[ctx->finding_count];
                    memset(f, 0, sizeof(finding_t));
                    f->type = FIND_MASS_ASSIGN;
                    f->severity = SEV_CRITICAL;
                    f->cvss_score = 8.2;
                    strncpy(f->url, ep->url, OMEGA_MAX_URL_LEN - 1);
                    snprintf(f->description, sizeof(f->description),
                        "Mass assignment: Hidden parameter '%s' accepted (response diff: %d→%d bytes)",
                        HIDDEN_PARAMS[i], baseline.body_len, resp.body_len);
                    snprintf(f->evidence, sizeof(f->evidence),
                        "Param: %s | Baseline: %d | Modified: %d | Status: %d",
                        HIDDEN_PARAMS[i], baseline.status_code, resp.status_code, resp.status_code);
                    f->confidence = 0.80;
                    strncpy(f->cwe_id, "CWE-915", sizeof(f->cwe_id) - 1);
                    strncpy(f->engine, "MassAssign", sizeof(f->engine) - 1);
                    f->timestamp = time_now();
                    ctx->finding_count++;
                    ctx->critical_count++;
                    log_info("🔴 CRITICAL: Mass assignment at %s via '%s'", ep->url, HIDDEN_PARAMS[i]);
                }
                http_response_free(&resp);
                http_response_free(&baseline);
                return 1;
            }
            http_response_free(&resp);
        }
    }
    
    http_response_free(&baseline);
    return 0;
}

int mass_content_type(const endpoint_t *ep, scan_context_t *ctx) {
    parsed_url_t parsed;
    url_parse(ep->url, &parsed);
    
    const char *types[] = {
        "application/json",
        "application/xml",
        "text/xml",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        NULL
    };
    
    const char *bodies[] = {
        "{\"admin\":true,\"test\":1}",
        "<request><admin>true</admin><test>1</test></request>",
        "<request><admin>true</admin><test>1</test></request>",
        "admin=true&test=1",
        NULL
    };
    
    /* Get baseline with standard form data */
    http_request_t baseline_req;
    memset(&baseline_req, 0, sizeof(baseline_req));
    strncpy(baseline_req.url, ep->url, OMEGA_MAX_URL_LEN - 1);
    strncpy(baseline_req.host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
    strncpy(baseline_req.path, ep->path, OMEGA_MAX_PATH_LEN - 1);
    baseline_req.port = parsed.port;
    baseline_req.ssl = parsed.ssl;
    baseline_req.method = HTTP_POST;
    baseline_req.timeout = OMEGA_DEFAULT_TIMEOUT;
    baseline_req.body = "test=1";
    baseline_req.body_len = 6;
    
    http_response_t baseline;
    if (http_request(&baseline_req, &baseline) != 0) return 0;
    
    for (int i = 0; types[i] && bodies[i]; i++) {
        http_request_t req;
        memset(&req, 0, sizeof(req));
        strncpy(req.url, ep->url, OMEGA_MAX_URL_LEN - 1);
        strncpy(req.host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
        strncpy(req.path, ep->path, OMEGA_MAX_PATH_LEN - 1);
        req.port = parsed.port;
        req.ssl = parsed.ssl;
        req.method = HTTP_POST;
        req.timeout = OMEGA_DEFAULT_TIMEOUT;
        req.body = (char *)bodies[i];
        req.body_len = strlen(bodies[i]);
        snprintf(req.headers, sizeof(req.headers), "Content-Type: %s\r\n", types[i]);
        
        http_response_t resp;
        if (http_request(&req, &resp) == 0) {
            bool diff = (resp.status_code != baseline.status_code) ||
                       (abs(resp.body_len - baseline.body_len) > 50);
            
            if (diff && (resp.status_code == 200 || resp.status_code == 201)) {
                if (ctx->finding_count < OMEGA_MAX_FINDINGS) {
                    finding_t *f = &ctx->findings[ctx->finding_count];
                    memset(f, 0, sizeof(finding_t));
                    f->type = FIND_MASS_CONTENT_TYPE;
                    f->severity = SEV_HIGH;
                    f->cvss_score = 7.5;
                    strncpy(f->url, ep->url, OMEGA_MAX_URL_LEN - 1);
                    snprintf(f->description, sizeof(f->description),
                        "Content-type switching: %s accepted with different response", types[i]);
                    f->confidence = 0.78;
                    strncpy(f->cwe_id, "CWE-915", sizeof(f->cwe_id) - 1);
                    strncpy(f->engine, "MassAssign", sizeof(f->engine) - 1);
                    f->timestamp = time_now();
                    ctx->finding_count++;
                    ctx->high_count++;
                    log_info("🟠 HIGH: Content-type switch at %s via %s", ep->url, types[i]);
                }
                http_response_free(&resp);
                http_response_free(&baseline);
                return 1;
            }
            http_response_free(&resp);
        }
    }
    
    http_response_free(&baseline);
    return 0;
}

int mass_run(scan_context_t *ctx) {
    if (!ctx) return -1;
    log_info("🔎 MassAssign: Testing for hidden parameters and content-type switching...");
    
    int tested = 0;
    for (int i = 0; i < ctx->endpoint_count && i < 15; i++) {
        if (ctx->endpoints[i].status_code >= 400) continue;
        if (!ctx->endpoints[i].has_api && !ctx->endpoints[i].has_forms) continue;
        tested++;
        if (ctx->progress_callback)
            ctx->progress_callback("MassAssign", tested, 15, ctx->endpoints[i].path);
        
        mass_hidden_params(&ctx->endpoints[i], ctx);
        mass_content_type(&ctx->endpoints[i], ctx);
    }
    
    log_info("🔎 MassAssign: Completed %d endpoint tests", tested);
    return 0;
}
