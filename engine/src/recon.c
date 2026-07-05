/*
 * OMEGA-ZERODAY HUNTER v2.0 — ReconSpider Engine (recon.c)
 * Endpoint discovery, HTML/JS/API parsing, robots.txt, sitemap, GraphQL
 * CLEAN REWRITE — no orphaned code, no broken functions
 */

#include "../include/omega.h"

/* ============================================================
 * HTML PARSER — Extract links, forms, scripts from HTML
 * ============================================================ */

int recon_parse_html(const char *html, const char *base_url, endpoint_t *eps, int *count) {
    if (!html || !base_url || !eps || !count) return -1;
    int orig = *count;
    const char *p = html;

    /* Extract href="..." from <a> tags */
    while ((p = strstr(p, "href=\"")) != NULL) {
        p += 6;
        const char *end = strchr(p, '"');
        if (!end) continue;
        int len = (int)(end - p);
        if (len <= 0 || len >= OMEGA_MAX_PATH_LEN) continue;

        char path[OMEGA_MAX_PATH_LEN] = {0};
        memcpy(path, p, len);

        /* Skip static assets, external, anchors */
        if (path[0] == '#' || strncmp(path, "http", 4) == 0 ||
            strncmp(path, "mailto:", 7) == 0 || strncmp(path, "javascript:", 11) == 0 ||
            strstr(path, ".css") || strstr(path, ".png") || strstr(path, ".jpg") ||
            strstr(path, ".gif") || strstr(path, ".svg") || strstr(path, ".ico") ||
            strstr(path, ".woff") || strstr(path, ".ttf")) {
            continue;
        }

        /* Dedup */
        bool found = false;
        for (int i = orig; i < *count; i++) {
            if (strcmp(eps[i].path, path) == 0) { found = true; break; }
        }
        if (found || *count >= OMEGA_MAX_ENDPOINTS) continue;

        endpoint_t *ep = &eps[*count];
        memset(ep, 0, sizeof(endpoint_t));
        strncpy(ep->path, path, OMEGA_MAX_PATH_LEN - 1);
        url_resolve(base_url, path, ep->url, OMEGA_MAX_URL_LEN);
        ep->has_params = strchr(path, '?') != NULL;
        (*count)++;
    }

    /* Extract src="..." from <script> tags for JS files */
    p = html;
    while ((p = strstr(p, "<script")) != NULL) {
        p++;
        const char *src = strstr(p, "src=\"");
        if (!src) src = strstr(p, "src='");
        if (!src) continue;

        char quote = (src[4] == '\'') ? '\'' : '"';
        src += 5;
        const char *end = strchr(src, quote);
        if (!end) continue;
        int len = (int)(end - src);
        if (len <= 0 || len >= OMEGA_MAX_PATH_LEN) continue;

        char path[OMEGA_MAX_PATH_LEN] = {0};
        memcpy(path, src, len);

        /* Only keep JS files */
        if (!strstr(path, ".js")) continue;

        /* Dedup */
        bool found = false;
        for (int i = orig; i < *count; i++) {
            if (strcmp(eps[i].path, path) == 0) { found = true; break; }
        }
        if (found || *count >= OMEGA_MAX_ENDPOINTS) continue;

        endpoint_t *ep = &eps[*count];
        memset(ep, 0, sizeof(endpoint_t));
        strncpy(ep->path, path, OMEGA_MAX_PATH_LEN - 1);
        url_resolve(base_url, path, ep->url, OMEGA_MAX_URL_LEN);
        ep->is_json = true;
        (*count)++;
    }

    /* Extract action="..." from <form> tags */
    p = html;
    while ((p = strstr(p, "<form")) != NULL) {
        p += 5;
        const char *action = strstr(p, "action=\"");
        if (!action) action = strstr(p, "action='");
        if (!action) continue;

        char quote = (action[7] == '\'') ? '\'' : '"';
        action += 8;
        const char *end = strchr(action, quote);
        if (!end) continue;
        int len = (int)(end - action);
        if (len <= 0 || len >= OMEGA_MAX_PATH_LEN) continue;

        char path[OMEGA_MAX_PATH_LEN] = {0};
        memcpy(path, action, len);

        /* Dedup */
        bool found = false;
        for (int i = orig; i < *count; i++) {
            if (strcmp(eps[i].path, path) == 0) { found = true; break; }
        }
        if (found || *count >= OMEGA_MAX_ENDPOINTS) continue;

        endpoint_t *ep = &eps[*count];
        memset(ep, 0, sizeof(endpoint_t));
        strncpy(ep->path, path, OMEGA_MAX_PATH_LEN - 1);
        url_resolve(base_url, path, ep->url, OMEGA_MAX_URL_LEN);
        ep->has_forms = true;
        ep->has_auth = str_contains_ci(p, "password") ||
                       str_contains_ci(p, "login") ||
                       str_contains_ci(p, "signin");
        (*count)++;
    }

    return *count - orig;
}

/* ============================================================
 * JAVASCRIPT PARSER — Extract API endpoints from JS code
 * ============================================================ */

int recon_parse_js(const char *js_content, const char *base_url, endpoint_t *eps, int *count) {
    if (!js_content || !base_url || !eps || !count) return -1;
    int orig = *count;

    const char *patterns[] = {
        "fetch(\"", "fetch('",
        "axios.get(\"", "axios.post(\"", "axios.put(\"", "axios.delete(",
        "axios.patch(",
        "axios({method:\"GET\",url:", "axios({method:\"POST\",url:",
        ".open(\"GET\",", ".open(\"POST\",",
        ".open(\"PUT\",", ".open(\"DELETE\",",
        "\"/api/", "'/api/",
        "\"/v1/", "'/v1/", "\"/v2/", "'/v2/",
        "new WebSocket(\"", "new WebSocket('",
        "wss://", "ws://",
        "baseUrl:", "baseURL:", "apiUrl:", "endpoint:",
        NULL
    };

    for (int i = 0; patterns[i]; i++) {
        const char *p = js_content;
        int plen = strlen(patterns[i]);

        while ((p = strstr(p, patterns[i])) != NULL) {
            p += plen;

            /* Extract the URL/path after the pattern */
            char quote = (*p == '"' || *p == '\'') ? *p : 0;
            if (quote) p++;

            /* Find end of URL */
            const char *end = p;
            while (*end && *end != quote && *end != ')' && *end != ';' &&
                   *end != '\n' && *end != '\'' && *end != '"') end++;

            int len = (int)(end - p);
            if (len < 2 || len >= OMEGA_MAX_PATH_LEN) continue;

            char path[OMEGA_MAX_PATH_LEN] = {0};
            memcpy(path, p, len);

            /* Skip non-path strings */
            if (strstr(path, "http://") || strstr(path, "https://")) continue;
            if (strstr(path, "localhost") || strstr(path, "127.0.0.1")) continue;
            if (path[0] != '/' && !strchr(path, '.')) continue;

            /* Dedup */
            bool found = false;
            for (int j = orig; j < *count; j++) {
                if (strcmp(eps[j].path, path) == 0) { found = true; break; }
            }
            if (found || *count >= OMEGA_MAX_ENDPOINTS) continue;

            endpoint_t *ep = &eps[*count];
            memset(ep, 0, sizeof(endpoint_t));
            strncpy(ep->path, path, OMEGA_MAX_PATH_LEN - 1);
            url_resolve(base_url, path, ep->url, OMEGA_MAX_URL_LEN);
            ep->has_api = true;
            (*count)++;
        }
    }

    return *count - orig;
}

/* ============================================================
 * ROBOTS.TXT PARSER
 * ============================================================ */

int recon_parse_robots(const char *robots_txt, endpoint_t *eps, int *count) {
    if (!robots_txt || !eps || !count) return -1;
    int orig = *count;

    const char *p = robots_txt;
    while ((p = strstr(p, "Disallow:")) != NULL) {
        p += 9;
        while (*p == ' ' || *p == '\t') p++;

        const char *end = p;
        while (*end && *end != '\n' && *end != '\r') end++;

        int len = (int)(end - p);
        if (len <= 1 || len >= OMEGA_MAX_PATH_LEN) continue;

        char path[OMEGA_MAX_PATH_LEN] = {0};
        memcpy(path, p, len);
        path[len] = '\0';

        /* Skip if already tracked */
        bool found = false;
        for (int i = orig; i < *count; i++) {
            if (strcmp(eps[i].path, path) == 0) { found = true; break; }
        }
        if (found || *count >= OMEGA_MAX_ENDPOINTS) continue;

        endpoint_t *ep = &eps[*count];
        memset(ep, 0, sizeof(endpoint_t));
        strncpy(ep->path, path, OMEGA_MAX_PATH_LEN - 1);
        ep->status_code = 403; /* Disallowed paths are often protected */
        (*count)++;
    }

    /* Also extract Allow: paths */
    p = robots_txt;
    while ((p = strstr(p, "Allow:")) != NULL) {
        p += 6;
        while (*p == ' ' || *p == '\t') p++;

        const char *end = p;
        while (*end && *end != '\n' && *end != '\r') end++;

        int len = (int)(end - p);
        if (len <= 1 || len >= OMEGA_MAX_PATH_LEN) continue;

        char path[OMEGA_MAX_PATH_LEN] = {0};
        memcpy(path, p, len);
        path[len] = '\0';

        bool found = false;
        for (int i = orig; i < *count; i++) {
            if (strcmp(eps[i].path, path) == 0) { found = true; break; }
        }
        if (found || *count >= OMEGA_MAX_ENDPOINTS) continue;

        endpoint_t *ep = &eps[*count];
        memset(ep, 0, sizeof(endpoint_t));
        strncpy(ep->path, path, OMEGA_MAX_PATH_LEN - 1);
        (*count)++;
    }

    /* Extract Sitemap: URLs */
    p = robots_txt;
    while ((p = strstr(p, "Sitemap:")) != NULL) {
        p += 8;
        while (*p == ' ' || *p == '\t') p++;

        const char *end = p;
        while (*end && *end != '\n' && *end != '\r') end++;

        int len = (int)(end - p);
        if (len < 10 || len >= OMEGA_MAX_URL_LEN) continue;

        /* Store as URL for later fetching */
        char url[OMEGA_MAX_URL_LEN] = {0};
        memcpy(url, p, len);
        url[len] = '\0';

        /* Extract path from full URL */
        const char *path_start = strstr(url, "://");
        if (path_start) {
            path_start = strchr(path_start + 3, '/');
            if (path_start) {
                char path[OMEGA_MAX_PATH_LEN] = {0};
                strncpy(path, path_start, OMEGA_MAX_PATH_LEN - 1);

                bool found = false;
                for (int i = orig; i < *count; i++) {
                    if (strcmp(eps[i].path, path) == 0) { found = true; break; }
                }
                if (!found && *count < OMEGA_MAX_ENDPOINTS) {
                    endpoint_t *ep = &eps[*count];
                    memset(ep, 0, sizeof(endpoint_t));
                    strncpy(ep->path, path, OMEGA_MAX_PATH_LEN - 1);
                    strncpy(ep->url, url, OMEGA_MAX_URL_LEN - 1);
                    (*count)++;
                }
            }
        }
    }

    return *count - orig;
}

/* ============================================================
 * SITEMAP.XML PARSER
 * ============================================================ */

int recon_parse_sitemap(const char *sitemap, endpoint_t *eps, int *count) {
    if (!sitemap || !eps || !count) return -1;
    int orig = *count;

    const char *p = sitemap;
    while ((p = strstr(p, "<loc>")) != NULL) {
        p += 5;
        const char *end = strstr(p, "</loc>");
        if (!end) continue;

        int len = (int)(end - p);
        if (len <= 0 || len >= OMEGA_MAX_URL_LEN) continue;

        char url[OMEGA_MAX_URL_LEN] = {0};
        memcpy(url, p, len);
        url[len] = '\0';

        /* Extract path from URL */
        const char *path_start = strstr(url, "://");
        if (!path_start) continue;
        path_start = strchr(path_start + 3, '/');
        if (!path_start) continue;

        char path[OMEGA_MAX_PATH_LEN] = {0};
        strncpy(path, path_start, OMEGA_MAX_PATH_LEN - 1);

        /* Dedup */
        bool found = false;
        for (int i = orig; i < *count; i++) {
            if (strcmp(eps[i].path, path) == 0) { found = true; break; }
        }
        if (found || *count >= OMEGA_MAX_ENDPOINTS) continue;

        endpoint_t *ep = &eps[*count];
        memset(ep, 0, sizeof(endpoint_t));
        strncpy(ep->path, path, OMEGA_MAX_PATH_LEN - 1);
        strncpy(ep->url, url, OMEGA_MAX_URL_LEN - 1);
        (*count)++;
    }

    return *count - orig;
}

/* ============================================================
 * GRAPHQL INTROSPECTION PROBE
 * ============================================================ */

int recon_graphql_probe(const char *base_url, endpoint_t *eps, int *count) {
    if (!base_url || !eps || !count) return -1;

    /* Common GraphQL endpoints */
    const char *graphql_paths[] = {
        "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
        "/v2/graphql", "/gql", "/query", "/_graphql", "/graphql/console",
        "/playground", "/altair", "/voyager", NULL
    };

    const char *introspection = "{\"query\":\"{ __schema { queryType { name } mutationType { name } types { name kind } } }\"}";
    int found = 0;

    for (int i = 0; graphql_paths[i] && *count < OMEGA_MAX_ENDPOINTS; i++) {
        char url[OMEGA_MAX_URL_LEN];
        snprintf(url, sizeof(url), "%s%s", base_url, graphql_paths[i]);

        parsed_url_t parsed;
        url_parse(url, &parsed);

        http_request_t req;
        memset(&req, 0, sizeof(req));
        strncpy(req.url, url, OMEGA_MAX_URL_LEN - 1);
        strncpy(req.host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
        strncpy(req.path, graphql_paths[i], OMEGA_MAX_PATH_LEN - 1);
        req.port = parsed.port;
        req.ssl = parsed.ssl;
        req.method = HTTP_POST;
        req.timeout = 5;
        req.body = (char *)introspection;
        req.body_len = strlen(introspection);
        strncpy(req.headers, "Content-Type: application/json\r\n", sizeof(req.headers) - 1);

        http_response_t resp;
        if (http_request(&req, &resp) == 0) {
            if (resp.status_code == 200 &&
                (str_contains(resp.body, "__schema") || str_contains(resp.body, "queryType"))) {
                endpoint_t *ep = &eps[*count];
                memset(ep, 0, sizeof(endpoint_t));
                strncpy(ep->path, graphql_paths[i], OMEGA_MAX_PATH_LEN - 1);
                url_resolve(base_url, graphql_paths[i], ep->url, OMEGA_MAX_URL_LEN);
                ep->has_api = true;
                ep->status_code = 200;
                (*count)++;
                found++;
            }
            http_response_free(&resp);
        }
    }

    return found;
}

/* ============================================================
 * SENSITIVE FILE DISCOVERY
 * ============================================================ */

static int discover_sensitive_files(const char *base_url, endpoint_t *eps, int *count, scan_context_t *ctx) {
    if (!base_url || !eps || !count) return 0;
    (void)ctx; /* unused parameter */

    const char *sensitive_paths[] = {
        "/.env", "/.git/config", "/.git/HEAD", "/wp-config.php.bak",
        "/.htaccess", "/.htpasswd", "/robots.txt", "/sitemap.xml",
        "/crossdomain.xml", "/.well-known/security.txt",
        "/server-status", "/server-info", "/phpinfo.php",
        "/.DS_Store", "/backup.sql", "/dump.sql", "/database.sql",
        "/config.php.bak", "/wp-config.php.old", "/web.config",
        "/.svn/entries", "/.svn/wc.db", "/WEB-INF/web.xml",
        "/.aws/credentials", "/.ssh/authorized_keys",
        "/actuator", "/actuator/env", "/actuator/health",
        "/api/v1/debug", "/api/debug", "/debug/vars",
        "/swagger.json", "/swagger-ui/", "/api-docs",
        "/openapi.json", "/openapi.yaml",
        "/.gitignore", "/README.md", "/CHANGELOG.md",
        "/wp-login.php", "/wp-admin/", "/administrator/",
        "/admin/login", "/login", "/signin", "/register",
        "/api/", "/api/v1/", "/api/v2/",
        "/console", "/debug", "/trace", "/status",
        "/metrics", "/prometheus", "/_stats",
        NULL
    };

    int orig = *count;
    parsed_url_t parsed;
    url_parse(base_url, &parsed);

    for (int i = 0; sensitive_paths[i] && *count < OMEGA_MAX_ENDPOINTS; i++) {
        char url[OMEGA_MAX_URL_LEN];
        snprintf(url, sizeof(url), "%s%s", base_url, sensitive_paths[i]);

        /* Check if already tracked */
        bool found = false;
        for (int j = orig; j < *count; j++) {
            if (strcmp(eps[j].path, sensitive_paths[i]) == 0) { found = true; break; }
        }
        if (found) continue;

        http_request_t req;
        memset(&req, 0, sizeof(req));
        strncpy(req.url, url, OMEGA_MAX_URL_LEN - 1);
        strncpy(req.host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
        strncpy(req.path, sensitive_paths[i], OMEGA_MAX_PATH_LEN - 1);
        req.port = parsed.port;
        req.ssl = parsed.ssl;
        req.method = HTTP_GET;
        req.timeout = 5;

        http_response_t resp;
        if (http_request(&req, &resp) == 0) {
            /* Store endpoints that returned interesting status codes */
            if (resp.status_code == 200 || resp.status_code == 403 ||
                resp.status_code == 401 || resp.status_code == 301 ||
                resp.status_code == 302) {

                endpoint_t *ep = &eps[*count];
                memset(ep, 0, sizeof(endpoint_t));
                strncpy(ep->path, sensitive_paths[i], OMEGA_MAX_PATH_LEN - 1);
                strncpy(ep->url, url, OMEGA_MAX_URL_LEN - 1);
                ep->status_code = resp.status_code;
                ep->has_api = (strstr(sensitive_paths[i], "api") != NULL);
                ep->has_auth = (resp.status_code == 401 || resp.status_code == 403);

                /* Detect tech stack from Server header (stored in path for now) */
                if (str_contains(resp.body, "Apache")) ep->has_api = true;
                else if (str_contains(resp.body, "nginx")) ep->has_api = true;
                else if (str_contains(resp.body, "IIS")) ep->has_api = true;
                else if (str_contains(resp.body, "LiteSpeed")) ep->has_api = true;

                (*count)++;
            }
            http_response_free(&resp);
        }
    }

    return *count - orig;
}

/* ============================================================
 * API PATH PROBING
 * ============================================================ */

int recon_api_probe(const char *base_url, endpoint_t *eps, int *count) {
    if (!base_url || !eps || !count) return -1;

    const char *api_paths[] = {
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/rest", "/rest/v1", "/rest/v2",
        "/graphql", "/gql",
        "/api/users", "/api/user", "/api/profile",
        "/api/auth", "/api/login", "/api/register",
        "/api/admin", "/api/config", "/api/settings",
        "/api/status", "/api/health", "/api/version",
        "/api/data", "/api/export", "/api/import",
        "/api/upload", "/api/search",
        "/v1", "/v2", "/v3",
        "/internal", "/internal/api",
        "/_api", "/__api__",
        NULL
    };

    int orig = *count;
    parsed_url_t parsed;
    url_parse(base_url, &parsed);

    for (int i = 0; api_paths[i] && *count < OMEGA_MAX_ENDPOINTS; i++) {
        /* Dedup */
        bool found = false;
        for (int j = orig; j < *count; j++) {
            if (strcmp(eps[j].path, api_paths[i]) == 0) { found = true; break; }
        }
        if (found) continue;

        char url[OMEGA_MAX_URL_LEN];
        snprintf(url, sizeof(url), "%s%s", base_url, api_paths[i]);

        http_request_t req;
        memset(&req, 0, sizeof(req));
        strncpy(req.url, url, OMEGA_MAX_URL_LEN - 1);
        strncpy(req.host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
        strncpy(req.path, api_paths[i], OMEGA_MAX_PATH_LEN - 1);
        req.port = parsed.port;
        req.ssl = parsed.ssl;
        req.method = HTTP_GET;
        req.timeout = 5;

        http_response_t resp;
        if (http_request(&req, &resp) == 0) {
            if (resp.status_code != 404 && resp.status_code != 0) {
                endpoint_t *ep = &eps[*count];
                memset(ep, 0, sizeof(endpoint_t));
                strncpy(ep->path, api_paths[i], OMEGA_MAX_PATH_LEN - 1);
                strncpy(ep->url, url, OMEGA_MAX_URL_LEN - 1);
                ep->status_code = resp.status_code;
                ep->has_api = true;

                /* Check if response is JSON */
                if (str_contains(resp.content_type, "json") ||
                    str_contains(resp.body, "{")) {
                    ep->is_json = true;
                }

                (*count)++;
            }
            http_response_free(&resp);
        }
    }

    return *count - orig;
}

/* ============================================================
 * MAIN RECON ORCHESTRATOR
 * ============================================================ */

int recon_run(scan_context_t *ctx) {
    if (!ctx) return -1;

    log_info("🕷️  ReconSpider: Starting endpoint discovery...");

    parsed_url_t parsed;
    url_parse(ctx->target_url, &parsed);

    /* Phase 1: Fetch main page */
    if (ctx->progress_callback)
        ctx->progress_callback("ReconSpider", 1, 7, "Fetching main page...");

    http_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.url, ctx->target_url, OMEGA_MAX_URL_LEN - 1);
    strncpy(req.host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
    strncpy(req.path, "/", OMEGA_MAX_PATH_LEN - 1);
    req.port = parsed.port;
    req.ssl = parsed.ssl;
    req.method = HTTP_GET;
    req.timeout = ctx->timeout;

    http_response_t resp;
    if (http_request(&req, &resp) == 0 && resp.body) {
        /* Parse HTML for links, scripts, forms */
        int before = ctx->endpoint_count;
        recon_parse_html(resp.body, ctx->target_url, ctx->endpoints, &ctx->endpoint_count);
        int found = ctx->endpoint_count - before;
        log_info("  📄 HTML: found %d endpoints from main page", found);
        ctx->total_requests++;
        http_response_free(&resp);
    }

    /* Phase 2: Sensitive file discovery */
    if (ctx->progress_callback)
        ctx->progress_callback("ReconSpider", 2, 7, "Discovering sensitive files...");

    int before = ctx->endpoint_count;
    discover_sensitive_files(ctx->target_url, ctx->endpoints, &ctx->endpoint_count, ctx);
    log_info("  🔍 Sensitive files: found %d paths", ctx->endpoint_count - before);

    /* Phase 3: Parse robots.txt */
    if (ctx->progress_callback)
        ctx->progress_callback("ReconSpider", 3, 7, "Parsing robots.txt...");

    snprintf(req.url, OMEGA_MAX_URL_LEN, "%s/robots.txt", ctx->target_url);
    strcpy(req.path, "/robots.txt");
    req.method = HTTP_GET;

    if (http_request(&req, &resp) == 0 && resp.body && resp.status_code == 200) {
        before = ctx->endpoint_count;
        recon_parse_robots(resp.body, ctx->endpoints, &ctx->endpoint_count);
        log_info("  🤖 robots.txt: found %d paths", ctx->endpoint_count - before);
        http_response_free(&resp);
    }

    /* Phase 4: Parse sitemap.xml */
    if (ctx->progress_callback)
        ctx->progress_callback("ReconSpider", 4, 7, "Parsing sitemap.xml...");

    snprintf(req.url, OMEGA_MAX_URL_LEN, "%s/sitemap.xml", ctx->target_url);
    strcpy(req.path, "/sitemap.xml");

    if (http_request(&req, &resp) == 0 && resp.body && resp.status_code == 200) {
        before = ctx->endpoint_count;
        recon_parse_sitemap(resp.body, ctx->endpoints, &ctx->endpoint_count);
        log_info("  🗺️  sitemap.xml: found %d URLs", ctx->endpoint_count - before);
        http_response_free(&resp);
    }

    /* Phase 5: JavaScript analysis */
    if (ctx->progress_callback)
        ctx->progress_callback("ReconSpider", 5, 7, "Analyzing JavaScript files...");

    for (int i = 0; i < ctx->endpoint_count && i < 20; i++) {
        if (ctx->endpoints[i].is_json && strstr(ctx->endpoints[i].path, ".js")) {
            http_request_t js_req;
            memset(&js_req, 0, sizeof(js_req));
            strncpy(js_req.url, ctx->endpoints[i].url, OMEGA_MAX_URL_LEN - 1);
            strncpy(js_req.host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
            strncpy(js_req.path, ctx->endpoints[i].path, OMEGA_MAX_PATH_LEN - 1);
            js_req.port = parsed.port;
            js_req.ssl = parsed.ssl;
            js_req.method = HTTP_GET;
            js_req.timeout = ctx->timeout;

            http_response_t js_resp;
            if (http_request(&js_req, &js_resp) == 0 && js_resp.body) {
                before = ctx->endpoint_count;
                recon_parse_js(js_resp.body, ctx->target_url, ctx->endpoints, &ctx->endpoint_count);
                if (ctx->endpoint_count - before > 0)
                    log_info("  📜 JS: found %d API endpoints in %s", ctx->endpoint_count - before, ctx->endpoints[i].path);
                http_response_free(&js_resp);
            }
        }
    }

    /* Phase 6: GraphQL introspection */
    if (ctx->progress_callback)
        ctx->progress_callback("ReconSpider", 6, 7, "Testing GraphQL introspection...");

    before = ctx->endpoint_count;
    recon_graphql_probe(ctx->target_url, ctx->endpoints, &ctx->endpoint_count);
    if (ctx->endpoint_count - before > 0)
        log_info("  🔮 GraphQL: introspection enabled! Found %d endpoints", ctx->endpoint_count - before);

    /* Phase 7: API path probing */
    if (ctx->progress_callback)
        ctx->progress_callback("ReconSpider", 7, 7, "Probing API paths...");

    before = ctx->endpoint_count;
    recon_api_probe(ctx->target_url, ctx->endpoints, &ctx->endpoint_count);
    log_info("  🌐 API probe: found %d active paths", ctx->endpoint_count - before);

    /* Set endpoint count */
    ctx->endpoints_discovered = ctx->endpoint_count;

    log_info("🕷️  ReconSpider: Complete — %d total endpoints discovered", ctx->endpoint_count);
    return 0;
}
