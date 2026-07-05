/*
 * OMEGA-ZERODAY HUNTER v2.0 — HTTP Client Engine
 *
 * Raw-socket HTTP/HTTPS client with:
 * - Connection pooling for speed
 * - TLS 1.2/1.3 support
 * - Custom header injection
 * - Redirect following (configurable)
 * - Timing measurement
 * - Connection reuse
 *
 * This is NOT a libcurl wrapper. This is a from-scratch
 * HTTP client built for vulnerability research.
 */

#include "../include/omega.h"

/* ============================================================
 * SSL/TLS CONTEXT
 * ============================================================ */

static SSL_CTX *g_ssl_ctx = NULL;
static int g_initialized = 0;

/* Connection pool entry */
typedef struct {
    int fd;
    SSL *ssl;
    char host[OMEGA_MAX_HOST_LEN];
    int port;
    bool in_use;
    double last_used;
    time_t created;
} conn_entry_t;

static conn_entry_t g_conn_pool[128];
static int g_pool_size = 0;
static pthread_mutex_t g_pool_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

int http_init(void) {
    if (g_initialized) return 0;
    
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx) {
        log_error("Failed to create SSL context");
        return -1;
    }
    
    /* Enable TLS 1.2 and 1.3 */
    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(g_ssl_ctx, TLS1_3_VERSION);
    
    /* Disable certificate verification for offensive use */
    SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
    
    memset(g_conn_pool, 0, sizeof(g_conn_pool));
    g_pool_size = 128;
    g_initialized = 1;
    
    log_verbose("HTTP engine initialized (TLS 1.2-1.3, conn pool: %d)", g_pool_size);
    return 0;
}

void http_cleanup(void) {
    if (!g_initialized) return;
    
    pthread_mutex_lock(&g_pool_mutex);
    for (int i = 0; i < g_pool_size; i++) {
        if (g_conn_pool[i].fd > 0) {
            if (g_conn_pool[i].ssl) {
                SSL_free(g_conn_pool[i].ssl);
            }
            close(g_conn_pool[i].fd);
            g_conn_pool[i].fd = -1;
        }
    }
    pthread_mutex_unlock(&g_pool_mutex);
    
    if (g_ssl_ctx) {
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
    }
    
    EVP_cleanup();
    g_initialized = 0;
}

/* ============================================================
 * URL PARSING
 * ============================================================ */

int url_parse(const char *url, parsed_url_t *out) {
    memset(out, 0, sizeof(parsed_url_t));
    
    const char *p = url;
    
    /* Parse scheme */
    if (strncmp(p, "https://", 8) == 0) {
        strcpy(out->scheme, "https");
        out->ssl = true;
        out->port = 443;
        p += 8;
    } else if (strncmp(p, "http://", 7) == 0) {
        strcpy(out->scheme, "http");
        out->ssl = false;
        out->port = 80;
        p += 7;
    } else {
        /* Default to http */
        strcpy(out->scheme, "http");
        out->ssl = false;
        out->port = 80;
    }
    
    /* Parse host */
    const char *host_start = p;
    const char *host_end = NULL;
    const char *port_start = NULL;
    const char *path_start = NULL;
    
    /* Find end of host */
    while (*p && *p != ':' && *p != '/' && *p != '?' && *p != '#') {
        p++;
    }
    host_end = p;
    
    /* Parse port */
    if (*p == ':') {
        p++;
        port_start = p;
        while (*p && *p != '/' && *p != '?' && *p != '#') p++;
        char port_str[16] = {0};
        int len = (int)(p - port_start);
        if (len > 0 && len < 16) {
            memcpy(port_str, port_start, len);
            out->port = atoi(port_str);
            if (out->port == 443) out->ssl = true;
        }
    }
    
    /* Parse path */
    if (*p == '/') {
        path_start = p;
        while (*p && *p != '?' && *p != '#') p++;
        int path_len = (int)(p - path_start);
        if (path_len >= OMEGA_MAX_PATH_LEN) path_len = OMEGA_MAX_PATH_LEN - 1;
        memcpy(out->path, path_start, path_len);
        out->path[path_len] = '\0';
    } else {
        strcpy(out->path, "/");
    }
    
    /* Parse query */
    if (*p == '?') {
        p++;
        const char *q_start = p;
        while (*p && *p != '#') p++;
        int q_len = (int)(p - q_start);
        if (q_len >= (int)sizeof(out->query)) q_len = (int)sizeof(out->query) - 1;
        memcpy(out->query, q_start, q_len);
        out->query[q_len] = '\0';
    }
    
    /* Parse fragment */
    if (*p == '#') {
        p++;
        int f_len = strlen(p);
        if (f_len >= (int)sizeof(out->fragment)) f_len = (int)sizeof(out->fragment) - 1;
        memcpy(out->fragment, p, f_len);
        out->fragment[f_len] = '\0';
    }
    
    /* Copy host */
    int host_len = (int)(host_end - host_start);
    if (host_len >= OMEGA_MAX_HOST_LEN) host_len = OMEGA_MAX_HOST_LEN - 1;
    memcpy(out->host, host_start, host_len);
    out->host[host_len] = '\0';
    
    return 0;
}

int url_build(const parsed_url_t *parsed, char *out, int out_len) {
    int written = snprintf(out, out_len, "%s://%s", parsed->scheme, parsed->host);
    
    if (parsed->port != 80 && parsed->port != 443) {
        written += snprintf(out + written, out_len - written, ":%d", parsed->port);
    }
    
    written += snprintf(out + written, out_len - written, "%s", parsed->path);
    
    if (parsed->query[0]) {
        written += snprintf(out + written, out_len - written, "?%s", parsed->query);
    }
    
    return written;
}

int url_resolve(const char *base, const char *relative, char *out, int out_len) {
    /* If relative is absolute, just copy it */
    if (strncmp(relative, "http://", 7) == 0 || strncmp(relative, "https://", 8) == 0) {
        strncpy(out, relative, out_len - 1);
        out[out_len - 1] = '\0';
        return 0;
    }
    
    parsed_url_t base_parsed;
    url_parse(base, &base_parsed);
    
    if (relative[0] == '/') {
        /* Absolute path */
        snprintf(out, out_len, "%s://%s%s", base_parsed.scheme, base_parsed.host, relative);
    } else {
        /* Relative path */
        char base_path[OMEGA_MAX_PATH_LEN];
        strncpy(base_path, base_parsed.path, sizeof(base_path) - 1);
        
        /* Find last slash */
        char *last_slash = strrchr(base_path, '/');
        if (last_slash) {
            *(last_slash + 1) = '\0';
        } else {
            strcpy(base_path, "/");
        }
        
        snprintf(out, out_len, "%s://%s%s%s", base_parsed.scheme, base_parsed.host, base_path, relative);
    }
    
    return 0;
}

/* ============================================================
 * CONNECTION MANAGEMENT
 * ============================================================ */

/* Find reusable connection in pool */
static int pool_find(const char *host, int port) {
    pthread_mutex_lock(&g_pool_mutex);
    for (int i = 0; i < g_pool_size; i++) {
        if (!g_conn_pool[i].in_use && g_conn_pool[i].fd > 0 &&
            strcmp(g_conn_pool[i].host, host) == 0 && g_conn_pool[i].port == port) {
            /* Check if connection is still alive (older than 60s = close) */
            if (time(NULL) - g_conn_pool[i].created < 60) {
                g_conn_pool[i].in_use = true;
                g_conn_pool[i].last_used = time_now();
                pthread_mutex_unlock(&g_pool_mutex);
                return i;
            }
            /* Too old, close it */
            if (g_conn_pool[i].ssl) SSL_free(g_conn_pool[i].ssl);
            close(g_conn_pool[i].fd);
            g_conn_pool[i].fd = -1;
            g_conn_pool[i].ssl = NULL;
        }
    }
    pthread_mutex_unlock(&g_pool_mutex);
    return -1;
}

/* Return connection to pool */
static void pool_return(int idx) {
    if (idx < 0 || idx >= g_pool_size) return;
    pthread_mutex_lock(&g_pool_mutex);
    g_conn_pool[idx].in_use = false;
    g_conn_pool[idx].last_used = time_now();
    pthread_mutex_unlock(&g_pool_mutex);
}

/* Close and remove connection from pool */
static void pool_close(int idx) {
    if (idx < 0 || idx >= g_pool_size) return;
    pthread_mutex_lock(&g_pool_mutex);
    if (g_conn_pool[idx].ssl) {
        SSL_free(g_conn_pool[idx].ssl);
        g_conn_pool[idx].ssl = NULL;
    }
    if (g_conn_pool[idx].fd > 0) {
        close(g_conn_pool[idx].fd);
        g_conn_pool[idx].fd = -1;
    }
    g_conn_pool[idx].in_use = false;
    pthread_mutex_unlock(&g_pool_mutex);
}

/* Create new TCP connection */
static int tcp_connect(const char *host, int port, int timeout_sec) {
    struct addrinfo hints, *res, *rp;
    int sockfd = -1;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);
    
    int ret = getaddrinfo(host, port_str, &hints, &res);
    if (ret != 0) {
        log_error("DNS resolution failed for %s: %s", host, gai_strerror(ret));
        return -1;
    }
    
    for (rp = res; rp; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd < 0) continue;
        
        /* Set non-blocking for timeout */
        int flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
        
        ret = connect(sockfd, rp->ai_addr, rp->ai_addrlen);
        if (ret < 0 && errno != EINPROGRESS) {
            close(sockfd);
            sockfd = -1;
            continue;
        }
        
        /* Wait for connection with timeout */
        fd_set write_fds;
        struct timeval tv;
        FD_ZERO(&write_fds);
        FD_SET(sockfd, &write_fds);
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;
        
        ret = select(sockfd + 1, NULL, &write_fds, NULL, &tv);
        if (ret <= 0) {
            close(sockfd);
            sockfd = -1;
            continue;
        }
        
        /* Check for connection errors */
        int err = 0;
        socklen_t errlen = sizeof(err);
        getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &errlen);
        if (err) {
            close(sockfd);
            sockfd = -1;
            continue;
        }
        
        /* Restore blocking mode */
        fcntl(sockfd, F_SETFL, flags);
        
        /* Set TCP_NODELAY for speed */
        int flag = 1;
        setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
        
        break;
    }
    
    freeaddrinfo(res);
    return sockfd;
}

/* Get SSL connection */
static SSL *ssl_connect(int fd, const char *host) {
    SSL *ssl = SSL_new(g_ssl_ctx);
    if (!ssl) return NULL;
    
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);
    
    /* Non-blocking SSL connect */
    int ret = SSL_connect(ssl);
    if (ret <= 0) {
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            /* Retry with select */
            fd_set fds;
            struct timeval tv = {.tv_sec = 10, .tv_usec = 0};
            
            FD_ZERO(&fds);
            FD_SET(fd, &fds);
            
            if (err == SSL_ERROR_WANT_READ)
                select(fd + 1, &fds, NULL, NULL, &tv);
            else
                select(fd + 1, NULL, &fds, NULL, &tv);
            
            ret = SSL_connect(ssl);
            if (ret <= 0) {
                SSL_free(ssl);
                return NULL;
            }
        } else {
            SSL_free(ssl);
            return NULL;
        }
    }
    
    return ssl;
}

/* ============================================================
 * REQUEST BUILDING
 * ============================================================ */

static int build_request(const http_request_t *req, char *buf, int buf_len) {
    const char *method_str = http_method_str(req->method);
    
    /* Build request line */
    int written = snprintf(buf, buf_len, "%s %s HTTP/1.1\r\n", method_str, req->path);
    
    /* Host header */
    if (req->port == 80 || req->port == 443) {
        written += snprintf(buf + written, buf_len - written, "Host: %s\r\n", req->host);
    } else {
        written += snprintf(buf + written, buf_len - written, "Host: %s:%d\r\n", req->host, req->port);
    }
    
    /* User-Agent */
    written += snprintf(buf + written, buf_len - written, 
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n");
    
    /* Accept */
    written += snprintf(buf + written, buf_len - written,
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n");
    
    /* Accept-Encoding */
    written += snprintf(buf + written, buf_len - written,
        "Accept-Encoding: identity\r\n");
    
    /* Connection: close for now (we manage our own connections) */
    written += snprintf(buf + written, buf_len - written, "Connection: close\r\n");
    
    /* Cookie */
    if (req->cookie[0]) {
        written += snprintf(buf + written, buf_len - written, "Cookie: %s\r\n", req->cookie);
    }
    
    /* Auth header */
    if (req->auth_header[0]) {
        written += snprintf(buf + written, buf_len - written, "Authorization: %s\r\n", req->auth_header);
    }
    
    /* Custom headers */
    if (req->headers[0]) {
        written += snprintf(buf + written, buf_len - written, "%s", req->headers);
    }
    
    /* Content-Type and Content-Length for body */
    if (req->body && req->body_len > 0) {
        /* Check if Content-Type is already in custom headers */
        if (!str_contains(req->headers, "Content-Type:") && !str_contains(req->headers, "content-type:")) {
            written += snprintf(buf + written, buf_len - written, "Content-Type: application/x-www-form-urlencoded\r\n");
        }
        written += snprintf(buf + written, buf_len - written, "Content-Length: %d\r\n", req->body_len);
    }
    
    /* End of headers */
    written += snprintf(buf + written, buf_len - written, "\r\n");
    
    /* Body */
    if (req->body && req->body_len > 0) {
        if (written + req->body_len < buf_len) {
            memcpy(buf + written, req->body, req->body_len);
            written += req->body_len;
        }
    }
    
    return written;
}

/* ============================================================
 * RESPONSE PARSING
 * ============================================================ */

static int parse_response(const char *raw, int raw_len, http_response_t *resp) {
    memset(resp, 0, sizeof(http_response_t));
    
    /* Find end of headers */
    const char *header_end = strstr(raw, "\r\n\r\n");
    if (!header_end) {
        /* Try just \n\n (malformed) */
        header_end = strstr(raw, "\n\n");
        if (!header_end) {
            resp->body = strdup("");
            return -1;
        }
    }
    
    int header_len = (int)(header_end - raw);
    if (header_len >= OMEGA_MAX_HEADER_LEN) header_len = OMEGA_MAX_HEADER_LEN - 1;
    memcpy(resp->headers, raw, header_len);
    resp->headers[header_len] = '\0';
    
    /* Parse status line */
    const char *p = raw;
    /* Skip HTTP/x.x */
    while (*p && *p != ' ') p++;
    p++; /* Skip space */
    
    /* Status code */
    char code_str[8] = {0};
    int i = 0;
    while (*p && *p != ' ' && i < 7) code_str[i++] = *p++;
    resp->status_code = atoi(code_str);
    
    /* Skip space */
    while (*p == ' ') p++;
    
    /* Status text */
    i = 0;
    while (*p && *p != '\r' && *p != '\n' && i < 127) resp->status_text[i++] = *p++;
    resp->status_text[i] = '\0';
    
    /* Parse headers */
    const char *h = raw;
    while (h < header_end) {
        const char *line_end = strstr(h, "\r\n");
        if (!line_end || line_end >= header_end) break;
        
        int line_len = (int)(line_end - h);
        
        if (strncasecmp(h, "Content-Type:", 13) == 0) {
            const char *val = h + 13;
            while (*val == ' ') val++;
            int vlen = line_len - (int)(val - h);
            if (vlen >= (int)sizeof(resp->content_type)) vlen = (int)sizeof(resp->content_type) - 1;
            memcpy(resp->content_type, val, vlen);
            resp->content_type[vlen] = '\0';
        } else if (strncasecmp(h, "Server:", 7) == 0) {
            const char *val = h + 7;
            while (*val == ' ') val++;
            int vlen = line_len - (int)(val - h);
            if (vlen >= (int)sizeof(resp->server)) vlen = (int)sizeof(resp->server) - 1;
            memcpy(resp->server, val, vlen);
            resp->server[vlen] = '\0';
        } else if (strncasecmp(h, "Set-Cookie:", 11) == 0) {
            const char *val = h + 11;
            while (*val == ' ') val++;
            int vlen = line_len - (int)(val - h);
            int cur_len = strlen(resp->set_cookie);
            if (cur_len + vlen < (int)sizeof(resp->set_cookie) - 2) {
                if (cur_len > 0) {
                    resp->set_cookie[cur_len++] = ';';
                    resp->set_cookie[cur_len++] = ' ';
                }
                memcpy(resp->set_cookie + cur_len, val, vlen);
                resp->set_cookie[cur_len + vlen] = '\0';
            }
        } else if (strncasecmp(h, "Location:", 9) == 0) {
            const char *val = h + 9;
            while (*val == ' ') val++;
            int vlen = line_len - (int)(val - h);
            if (vlen >= (int)sizeof(resp->location)) vlen = (int)sizeof(resp->location) - 1;
            memcpy(resp->location, val, vlen);
            resp->location[vlen] = '\0';
        } else if (strncasecmp(h, "Content-Length:", 15) == 0) {
            const char *val = h + 15;
            while (*val == ' ') val++;
            resp->body_len = atoi(val);
        }
        
        h = line_end + 2;
    }
    
    /* Extract body */
    const char *body_start = header_end + 4;
    int body_available = raw_len - (int)(body_start - raw);
    
    if (body_available > 0) {
        int body_size = resp->body_len > 0 ? resp->body_len : body_available;
        if (body_size > body_available) body_size = body_available;
        if (body_size > OMEGA_MAX_BODY_LEN) body_size = OMEGA_MAX_BODY_LEN;
        
        resp->body = malloc(body_size + 1);
        if (resp->body) {
            memcpy(resp->body, body_start, body_size);
            resp->body[body_size] = '\0';
            resp->body_len = body_size;
        }
    } else {
        resp->body = strdup("");
        resp->body_len = 0;
    }
    
    return 0;
}

/* ============================================================
 * CORE HTTP REQUEST FUNCTION
 * ============================================================ */

int http_request(const http_request_t *req, http_response_t *resp) {
    double start_time = time_now();
    memset(resp, 0, sizeof(http_response_t));
    
    /* Try to reuse connection from pool */
    int pool_idx = pool_find(req->host, req->port);
    int fd = -1;
    SSL *ssl = NULL;
    bool new_connection = true;
    
    if (pool_idx >= 0) {
        /* Reuse existing connection */
        fd = g_conn_pool[pool_idx].fd;
        ssl = g_conn_pool[pool_idx].ssl;
        new_connection = false;
    }
    
    /* Create new connection if needed */
    if (fd < 0) {
        fd = tcp_connect(req->host, req->port, req->timeout > 0 ? req->timeout : OMEGA_DEFAULT_TIMEOUT);
        if (fd < 0) {
            resp->connection_error = true;
            resp->response_time = time_now() - start_time;
            return -1;
        }
        
        if (req->ssl) {
            ssl = ssl_connect(fd, req->host);
            if (!ssl) {
                close(fd);
                resp->connection_error = true;
                resp->response_time = time_now() - start_time;
                return -1;
            }
        }
        
        /* Add to pool */
        pthread_mutex_lock(&g_pool_mutex);
        for (int i = 0; i < g_pool_size; i++) {
            if (g_conn_pool[i].fd <= 0 && !g_conn_pool[i].in_use) {
                g_conn_pool[i].fd = fd;
                g_conn_pool[i].ssl = ssl;
                strncpy(g_conn_pool[i].host, req->host, OMEGA_MAX_HOST_LEN - 1);
                g_conn_pool[i].port = req->port;
                g_conn_pool[i].in_use = true;
                g_conn_pool[i].last_used = time_now();
                g_conn_pool[i].created = time_now();
                pool_idx = i;
                break;
            }
        }
        pthread_mutex_unlock(&g_pool_mutex);
    }
    
    /* Build request */
    char request_buf[8192];
    int request_len = build_request(req, request_buf, sizeof(request_buf));
    
    /* Send request */
    int sent = 0;
    while (sent < request_len) {
        int n;
        if (ssl) {
            n = SSL_write(ssl, request_buf + sent, request_len - sent);
        } else {
            n = write(fd, request_buf + sent, request_len - sent);
        }
        
        if (n <= 0) {
            /* Connection broken, retry with new connection */
            pool_close(pool_idx);
            if (ssl) { SSL_free(ssl); ssl = NULL; }
            close(fd);
            
            fd = tcp_connect(req->host, req->port, req->timeout > 0 ? req->timeout : OMEGA_DEFAULT_TIMEOUT);
            if (fd < 0) {
                resp->connection_error = true;
                resp->response_time = time_now() - start_time;
                return -1;
            }
            if (req->ssl) {
                ssl = ssl_connect(fd, req->host);
                if (!ssl) {
                    close(fd);
                    resp->connection_error = true;
                    resp->response_time = time_now() - start_time;
                    return -1;
                }
            }
            sent = 0;
            continue;
        }
        sent += n;
    }
    
    /* Receive response */
    char response_buf[OMEGA_MAX_BODY_LEN + OMEGA_MAX_HEADER_LEN + 1024];
    int total_received = 0;
    int timeout_sec = req->timeout > 0 ? req->timeout : OMEGA_DEFAULT_TIMEOUT;
    
    while (total_received < (int)sizeof(response_buf) - 1) {
        /* Check timeout */
        if (time_now() - start_time > timeout_sec) {
            resp->timed_out = true;
            break;
        }
        
        int n;
        if (ssl) {
            n = SSL_read(ssl, response_buf + total_received, 
                        sizeof(response_buf) - total_received - 1);
        } else {
            n = read(fd, response_buf + total_received, 
                    sizeof(response_buf) - total_received - 1);
        }
        
        if (n <= 0) break;
        total_received += n;
        
        /* Check if we have complete response */
        response_buf[total_received] = '\0';
        if (strstr(response_buf, "\r\n\r\n")) {
            /* We have headers, check if body is complete */
            const char *body_start = strstr(response_buf, "\r\n\r\n") + 4;
            int header_len = (int)(body_start - response_buf);
            
            /* Check Content-Length */
            const char *cl = strcasestr(response_buf, "Content-Length:");
            if (cl) {
                int content_len = atoi(cl + 15);
                int body_received = total_received - header_len;
                if (body_received >= content_len) break;
            } else {
                /* No Content-Length, check for Connection: close */
                if (strcasestr(response_buf, "Connection: close")) {
                    break;
                }
            }
        }
    }
    
    response_buf[total_received] = '\0';
    resp->response_time = time_now() - start_time;
    
    /* Parse response */
    if (total_received > 0) {
        parse_response(response_buf, total_received, resp);
    }
    
    /* Return connection to pool */
    if (pool_idx >= 0) {
        pool_return(pool_idx);
    } else {
        if (ssl) SSL_free(ssl);
        close(fd);
    }
    
    return 0;
}

/* ============================================================
 * HELPER FUNCTIONS
 * ============================================================ */

const char *http_method_str(http_method_t method) {
    switch (method) {
        case HTTP_GET:     return "GET";
        case HTTP_POST:    return "POST";
        case HTTP_PUT:     return "PUT";
        case HTTP_DELETE:  return "DELETE";
        case HTTP_PATCH:   return "PATCH";
        case HTTP_HEAD:    return "HEAD";
        case HTTP_OPTIONS: return "OPTIONS";
        case HTTP_TRACE:   return "TRACE";
        default:           return "GET";
    }
}

void http_response_free(http_response_t *resp) {
    if (resp && resp->body) {
        free(resp->body);
        resp->body = NULL;
    }
}

/* ============================================================
 * RAW TCP SEND (for HTTP smuggling)
 * ============================================================ */

int smuggle_raw_send(const char *host, int port, bool ssl_flag,
                     const char *payload, int payload_len,
                     char *response, int resp_len) {
    int fd = tcp_connect(host, port, 10);
    if (fd < 0) return -1;
    
    SSL *ssl = NULL;
    if (ssl_flag) {
        ssl = ssl_connect(fd, host);
        if (!ssl) {
            close(fd);
            return -1;
        }
    }
    
    /* Send raw payload (no HTTP framing) */
    int sent = 0;
    while (sent < payload_len) {
        int n;
        if (ssl) {
            n = SSL_write(ssl, payload + sent, payload_len - sent);
        } else {
            n = write(fd, payload + sent, payload_len - sent);
        }
        if (n <= 0) break;
        sent += n;
    }
    
    /* Read response */
    int total = 0;
    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    fd_set fds;
    
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    
    if (select(fd + 1, &fds, NULL, NULL, &tv) > 0) {
        if (ssl) {
            total = SSL_read(ssl, response, resp_len - 1);
        } else {
            total = read(fd, response, resp_len - 1);
        }
    }
    
    if (total > 0) response[total] = '\0';
    else response[0] = '\0';
    
    if (ssl) SSL_free(ssl);
    close(fd);
    
    return total;
}
