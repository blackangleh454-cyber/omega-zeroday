/*
 * OMEGA-ZERODAY HUNTER v2.0 — Main Entry Point
 * CLI parsing, scan orchestration, report output (JSON + text)
 */

#include "../include/omega.h"
#include <getopt.h>
#include <signal.h>
#include <unistd.h>

/* External engine runners */
extern int recon_run(scan_context_t *ctx);
extern int auth_run(scan_context_t *ctx);
extern int race_run(scan_context_t *ctx);
extern int ssrf_run(scan_context_t *ctx);
extern int mass_run(scan_context_t *ctx);
extern int smuggle_run(scan_context_t *ctx);
extern int logic_run(scan_context_t *ctx);
extern int crypto_run(scan_context_t *ctx);
extern int chain_analyze(scan_context_t *ctx);

/* Globals */
int g_verbose = 0;
static volatile int g_running = 1;
static int g_json_output = 0;

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
    fprintf(stderr, "\n\033[1;33m⚠ Scan interrupted\033[0m\n");
}

static void print_banner(void) {
    printf("\n");
    printf("\033[1;31m");
    printf("  ██████  ██ ███████ ████████  ██████   ██████  ██████  ██████  ███████\n");
    printf("  ██   ██ ██ ██         ██    ██    ██ ██      ██    ██ ██   ██ ██     \n");
    printf("  ██████  ██ ███████    ██    ██    ██ ██      ██    ██ ██████  █████  \n");
    printf("  ██   ██ ██      ██    ██    ██    ██ ██      ██    ██ ██   ██ ██     \n");
    printf("  ██████  ██ ███████    ██     ██████   ██████  ██████  ██   ██ ███████\n");
    printf("\033[0m");
    printf("\033[1;33m");
    printf("       ⚡ Z E R O D A Y   H U N T E R   v%s ⚡\n", OMEGA_VERSION);
    printf("\033[0m");
    printf("\033[0;37m");
    printf("       Real Vulnerability Discovery Engine\n");
    printf("       By %s | C Engine + Python UI\n", OMEGA_AUTHOR);
    printf("\033[0m\n\n");
}

static void usage(void) {
    printf("Usage: omega-engine [OPTIONS] <target_url>\n\n");
    printf("Options:\n");
    printf("  --engines <list>   Comma-separated engines (default: all)\n");
    printf("                     recon,auth,race,ssrf,mass,smuggle,logic,crypto\n");
    printf("  --threads <n>      Parallel threads (default: 20)\n");
    printf("  --timeout <s>      Request timeout (default: 10)\n");
    printf("  --cookie <str>     Cookie header value\n");
    printf("  --json             Output as JSON\n");
    printf("  --quiet            Suppress progress bars\n");
    printf("  -h, --help         Show this help\n");
    printf("  -v, --version      Show version\n\n");
    printf("Examples:\n");
    printf("  omega-engine https://target.com\n");
    printf("  omega-engine https://target.com --engines auth,race\n");
    printf("  omega-engine https://target.com --json --quiet\n\n");
}

/* Progress callback: prints a progress bar */
static void progress_cb(const char *engine, int current, int total, const char *msg) {
    int pct = (total > 0) ? (current * 100 / total) : 0;
    int bar = 30;
    int filled = (pct * bar) / 100;
    fprintf(stderr, "\r\033[0;37m  %s: [", engine);
    for (int i = 0; i < bar; i++)
        fprintf(stderr, i < filled ? "\033[1;32m█" : "\033[0;37m░");
    fprintf(stderr, "\033[0m] %3d%% %s  ", pct, msg);
    fflush(stderr);
}

/* Phase indicator */
static void phase_cb(int phase, int total, const char *name) {
    if (g_json_output) return;  /* Suppress phase output in JSON mode */
    fprintf(stderr, "\n\033[1;36m  ═══════════════════════════════════════\033[0m\n");
    fprintf(stderr, "\033[1;36m  PHASE %d/%d: %s\033[0m\n", phase, total, name);
    fprintf(stderr, "\033[1;36m  ═══════════════════════════════════════\033[0m\n");
}

/* JSON output */
static void output_json(scan_context_t *ctx) {
    printf("{\n");
    printf("  \"tool\": \"%s\",\n", OMEGA_NAME);
    printf("  \"version\": \"%s\",\n", OMEGA_VERSION);
    printf("  \"target\": \"%s\",\n", ctx->target_url);
    printf("  \"duration\": %.1f,\n", ctx->total_time);
    printf("  \"endpoints\": %d,\n", ctx->endpoints_discovered);
    printf("  \"requests\": %d,\n", ctx->total_requests);
    printf("  \"summary\": {\n");
    printf("    \"critical\": %d,\n", ctx->critical_count);
    printf("    \"high\": %d,\n", ctx->high_count);
    printf("    \"medium\": %d,\n", ctx->medium_count);
    printf("    \"total\": %d\n", ctx->finding_count);
    printf("  },\n");
    printf("  \"chains\": %d,\n", ctx->chain_count);
    printf("  \"findings\": [\n");
    for (int i = 0; i < ctx->finding_count; i++) {
        finding_t *f = &ctx->findings[i];
        printf("    {\"severity\":\"%s\",\"type\":\"%s\",\"cvss\":%.1f,"
               "\"confidence\":%.2f,\"url\":\"%s\",\"description\":\"%s\","
               "\"evidence\":\"%s\",\"cwe\":\"%s\",\"engine\":\"%s\"}%s\n",
               severity_str(f->severity), finding_type_str(f->type), f->cvss_score,
               f->confidence, f->url, f->description, f->evidence,
               f->cwe_id, f->engine, i < ctx->finding_count - 1 ? "," : "");
    }
    printf("  ],\n");
    printf("  \"chains_detail\": [\n");
    for (int i = 0; i < ctx->chain_count; i++) {
        chain_t *c = &ctx->chains[i];
        printf("    {\"severity\":\"%s\",\"cvss\":%.1f,\"steps\":%d,"
               "\"description\":\"%s\"}%s\n",
               severity_str(c->combined_severity), c->combined_cvss,
               c->step_count, c->description,
               i < ctx->chain_count - 1 ? "," : "");
    }
    printf("  ]\n}\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) { print_banner(); usage(); return 1; }

    /* Signal handler */
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    /* Init scan context */
    scan_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.threads = OMEGA_DEFAULT_THREADS;
    ctx.timeout = OMEGA_DEFAULT_TIMEOUT;
    ctx.engines = ENGINE_ALL;
    ctx.progress_callback = progress_cb;
    ctx.phase_callback = phase_cb;
    pthread_mutex_init(&ctx.mutex, NULL);

    /* Parse args */
    int json_output = 0, quiet = 0;
    const char *target = NULL;
    const char *cookie = NULL;

    static struct option long_opts[] = {
        {"engines", required_argument, 0, 'e'},
        {"threads", required_argument, 0, 't'},
        {"timeout", required_argument, 0, 'T'},
        {"cookie",  required_argument, 0, 'c'},
        {"json",    no_argument,       0, 'j'},
        {"quiet",   no_argument,       0, 'q'},
        {"verbose", no_argument,       0, 'V'},
        {"help",    no_argument,       0, 'h'},
        {"version", no_argument,       0, 'v'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "e:t:T:c:jqVhv", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'e':
                ctx.engines = 0;
                { char *tok = strtok(optarg, ",");
                  while (tok) {
                    if (!strcmp(tok, "all"))       ctx.engines = ENGINE_ALL;
                    else if (!strcmp(tok, "recon"))     ctx.engines |= ENGINE_RECON;
                    else if (!strcmp(tok, "auth")) ctx.engines |= ENGINE_AUTH;
                    else if (!strcmp(tok, "race")) ctx.engines |= ENGINE_RACE;
                    else if (!strcmp(tok, "ssrf")) ctx.engines |= ENGINE_SSRF;
                    else if (!strcmp(tok, "mass")) ctx.engines |= ENGINE_MASS;
                    else if (!strcmp(tok, "smuggle")) ctx.engines |= ENGINE_SMUGGLE;
                    else if (!strcmp(tok, "logic")) ctx.engines |= ENGINE_LOGIC;
                    else if (!strcmp(tok, "crypto")) ctx.engines |= ENGINE_CRYPTO;
                    else fprintf(stderr, "Unknown engine: %s\n", tok);
                    tok = strtok(NULL, ",");
                  }
                }
                break;
            case 't': ctx.threads = atoi(optarg); break;
            case 'T': ctx.timeout = atoi(optarg); break;
            case 'c': cookie = optarg; break;
            case 'j': json_output = 1; g_json_output = 1; ctx.progress_callback = NULL; ctx.phase_callback = NULL; log_set_level(LOG_WARN); break;
            case 'q': quiet = 1; ctx.progress_callback = NULL; break;
            case 'V': g_verbose = 1; break;
            case 'h': print_banner(); usage(); return 0;
            case 'v': printf("omega-engine v%s\n", OMEGA_VERSION); return 0;
            default:  usage(); return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: No target URL specified\n");
        usage();
        return 1;
    }
    target = argv[optind];

    /* Parse target URL */
    strncpy(ctx.target_url, target, OMEGA_MAX_URL_LEN - 1);
    parsed_url_t parsed;
    if (url_parse(target, &parsed) != 0) {
        fprintf(stderr, "Error: Invalid URL: %s\n", target);
        return 1;
    }
    strncpy(ctx.target_host, parsed.host, OMEGA_MAX_HOST_LEN - 1);
    ctx.target_port = parsed.port;
    ctx.target_ssl = parsed.ssl;
    url_build(&parsed, ctx.base_url, sizeof(ctx.base_url));

    if (cookie) {
        strncpy(ctx.cookie, cookie, sizeof(ctx.cookie) - 1);
    }

    /* Init HTTP */
    http_init();

    if (!quiet && !g_json_output) {
        print_banner();
        printf("  \033[1;37mTarget:  \033[1;32m%s\033[0m\n", ctx.target_url);
        printf("  \033[1;37mHost:    \033[0;36m%s\033[0m\n", ctx.target_host);
        printf("  \033[1;37mPort:    \033[0;36m%d\033[0m | SSL: %s\n", ctx.target_port, ctx.target_ssl ? "Yes" : "No");
        printf("  \033[1;37mThreads: \033[0;36m%d\033[0m | Timeout: %ds\n\n", ctx.threads, ctx.timeout);
    }

    /* Count engines */
    int total_engines = 0;
    if (ctx.engines & ENGINE_RECON) total_engines++;
    if (ctx.engines & ENGINE_AUTH) total_engines++;
    if (ctx.engines & ENGINE_RACE) total_engines++;
    if (ctx.engines & ENGINE_SSRF) total_engines++;
    if (ctx.engines & ENGINE_MASS) total_engines++;
    if (ctx.engines & ENGINE_SMUGGLE) total_engines++;
    if (ctx.engines & ENGINE_LOGIC) total_engines++;
    if (ctx.engines & ENGINE_CRYPTO) total_engines++;

    if (!quiet)
        printf("  \033[1;37mEngines: \033[0;36m%d\033[0m active\n\n", total_engines);

    double scan_start = time_now();
    int engine_num = 0;
    int phases = total_engines > 1 ? 4 : 3;

    /* Phase 1: Recon */
    if (ctx.engines & ENGINE_RECON) {
        if (!quiet) phase_cb(1, phases, "Endpoint Discovery");
        recon_run(&ctx);
        engine_num++;
    }

    /* Phase 2: Detection */
    if (!quiet && total_engines > 1) phase_cb(2, phases, "Vulnerability Detection");

    if ((ctx.engines & ENGINE_AUTH) && ctx.endpoint_count > 0) { auth_run(&ctx); engine_num++; }
    if ((ctx.engines & ENGINE_RACE) && ctx.endpoint_count > 0) { race_run(&ctx); engine_num++; }
    if ((ctx.engines & ENGINE_SSRF) && ctx.endpoint_count > 0) { ssrf_run(&ctx); engine_num++; }
    if ((ctx.engines & ENGINE_MASS) && ctx.endpoint_count > 0) { mass_run(&ctx); engine_num++; }
    if ((ctx.engines & ENGINE_SMUGGLE) && ctx.endpoint_count > 0) { smuggle_run(&ctx); engine_num++; }
    if ((ctx.engines & ENGINE_LOGIC) && ctx.endpoint_count > 0) { logic_run(&ctx); engine_num++; }
    if ((ctx.engines & ENGINE_CRYPTO) && ctx.endpoint_count > 0) { crypto_run(&ctx); engine_num++; }

    /* Phase 3: Chain Analysis */
    if (!quiet) phase_cb(phases > 1 ? 3 : 2, phases, "Vulnerability Chain Analysis");
    chain_analyze(&ctx);

    ctx.total_time = time_now() - scan_start;

    /* Cleanup */
    http_cleanup();
    pthread_mutex_destroy(&ctx.mutex);

    /* Output */
    if (json_output) {
        output_json(&ctx);
    } else if (!quiet && !g_json_output) {
        printf("\n  \033[1;31m═══════════════════════════════════════════\033[0m\n");
        printf("  \033[1;31m  🎯 SCAN COMPLETE\033[0m\n");
        printf("  \033[1;31m═══════════════════════════════════════════\033[0m\n");
        printf("  \033[1;37m  Duration:    \033[1;36m%.1fs\033[0m\n", ctx.total_time);
        printf("  \033[1;37m  Endpoints:   \033[1;36m%d\033[0m\n", ctx.endpoints_discovered);
        printf("  \033[1;37m  Requests:    \033[1;36m%d\033[0m\n", ctx.total_requests);
        printf("\n");
        printf("  \033[1;31m  🔴 CRITICAL: %d\033[0m\n", ctx.critical_count);
        printf("  \033[1;33m  🟠 HIGH:     %d\033[0m\n", ctx.high_count);
        printf("  \033[0;33m  🟡 MEDIUM:   %d\033[0m\n", ctx.medium_count);
        printf("  \033[0;37m  📊 Total:    %d\033[0m\n", ctx.finding_count);
        printf("  \033[1;35m  ⛓️  Chains:   %d\033[0m\n", ctx.chain_count);

        if (ctx.finding_count > 0) {
            printf("\n  \033[1;37m═══════════════════════════════════════════\033[0m\n");
            printf("  \033[1;37m  FINDINGS\033[0m\n");
            printf("  \033[1;37m═══════════════════════════════════════════\033[0m\n\n");
            for (int i = 0; i < ctx.finding_count; i++) {
                finding_t *f = &ctx.findings[i];
                printf("  %s[%s]\033[0m \033[1;37m%s\033[0m — %s\n",
                       severity_color(f->severity), severity_str(f->severity),
                       finding_type_str(f->type), f->description);
                printf("    URL: %s\n    CVSS: %.1f | CWE: %s | Confidence: %.0f%%\n",
                       f->url, f->cvss_score, f->cwe_id, f->confidence * 100);
                printf("    Evidence: %s\n\n", f->evidence);
            }
        }

        if (ctx.chain_count > 0) {
            printf("  \033[1;35m═══════════════════════════════════════════\033[0m\n");
            printf("  \033[1;35m  🔗 EXPLOIT CHAINS\033[0m\n");
            printf("  \033[1;35m═══════════════════════════════════════════\033[0m\n\n");
            for (int i = 0; i < ctx.chain_count; i++) {
                printf("  \033[1;35mChain %d (CVSS %.1f):\033[0m %s\n",
                       i + 1, ctx.chains[i].combined_cvss, ctx.chains[i].description);
            }
            printf("\n");
        }
    }

    return ctx.critical_count > 0 ? 2 : (ctx.high_count > 0 ? 1 : 0);
}
