package hardening

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

func ImageRecipe(dir string, c Config) (string, error) {
	suffix := fmt.Sprintf("\nWORKDIR /app\nENV HOME=/tmp TMPDIR=/tmp\nUSER 65532:65532\nEXPOSE %d\n", c.Port)
	switch c.Runtime {
	case "go":
		entry := c.Entry
		if entry != "." {
			entry = "./" + entry
		}
		return fmt.Sprintf(`FROM golang:%s-bookworm AS build
ENV GOTOOLCHAIN=local
WORKDIR /src
COPY app/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app %s
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/app /app/server
%s
ENV PORT=%d
ENTRYPOINT ["/app/server"]
`, c.Version, entry, suffix, c.Port), nil
	case "node", "next":
		build := ""
		if c.Build {
			build = "RUN npm run build\n"
		}
		copyApp := "COPY --from=build /src/ /app/\n"
		entry := c.Entry
		if c.Runtime == "next" {
			build += "RUN test -f .next/standalone/server.js && mkdir -p public\n"
			copyApp = "COPY --from=build /src/.next/standalone/ /app/\nCOPY --from=build /src/.next/static/ /app/.next/static/\nCOPY --from=build /src/public/ /app/public/\n"
			entry = "server.js"
		}
		return fmt.Sprintf(`FROM node:%s-trixie-slim AS build
ENV npm_config_engine_strict=true
WORKDIR /src
COPY app/ ./
RUN npm ci --no-audit --no-fund
%sRUN npm prune --omit=dev --no-audit --no-fund
FROM gcr.io/distroless/nodejs%s-debian13:nonroot
%s%s
ENV NODE_ENV=production PORT=%d HOSTNAME=0.0.0.0
ENTRYPOINT ["/nodejs/bin/node"]
CMD ["%s"]
`, c.Version, build, c.Version, copyApp, suffix, c.Port, entry), nil
	case "php":
		extensions, packages, err := phpExtensions(dir)
		if err != nil {
			return "", err
		}
		install := ""
		if len(packages) > 0 {
			install = "RUN apt-get update && apt-get install -y --no-install-recommends " + strings.Join(packages, " ") + " && rm -rf /var/lib/apt/lists/*\n"
		}
		for _, ext := range extensions {
			install += fmt.Sprintf("RUN php -r 'exit(extension_loaded(\"%s\") ? 0 : 1);' || docker-php-ext-install %s\n", ext, ext)
		}
		return fmt.Sprintf(`FROM composer:2 AS composer
FROM php:%s-fpm-trixie AS build
COPY --from=composer /usr/bin/composer /usr/local/bin/composer
%sWORKDIR /src
COPY app/ ./
RUN composer install --no-dev --prefer-dist --no-interaction --optimize-autoloader && composer check-platform-reqs --no-dev
COPY collect-php-runtime.sh /collect-php-runtime.sh
RUN sh /collect-php-runtime.sh
FROM gcr.io/distroless/base-debian13:nonroot
COPY --from=build /runtime/ /
COPY --from=build /src/ /app/
COPY php.ini /usr/local/etc/php/conf.d/zz-breachbench.ini
COPY php-fpm.conf /usr/local/etc/php-fpm.conf
%s
ENV PHP_INI_SCAN_DIR=/usr/local/etc/php/conf.d
ENTRYPOINT ["/usr/local/sbin/php-fpm", "--nodaemonize", "--fpm-config", "/usr/local/etc/php-fpm.conf"]
`, c.Version, install, suffix), nil
	}
	return "", fmt.Errorf("unsupported runtime")
}

// Unknown extensions fail explicitly; installing guessed packages produces
// images that build but fail under real traffic.
func phpExtensions(dir string) ([]string, []string, error) {
	var p Composer
	if err := readJSON(filepath.Join(dir, "composer.json"), &p, false); err != nil {
		return nil, nil, err
	}
	var lock struct {
		Packages []Composer `json:"packages"`
	}
	if err := readJSON(filepath.Join(dir, "composer.lock"), &lock, false); err != nil {
		return nil, nil, err
	}
	reqs := map[string]bool{}
	for _, r := range append(lock.Packages, p) {
		for name := range r.Require {
			if strings.HasPrefix(name, "ext-") {
				reqs[strings.TrimPrefix(name, "ext-")] = true
			}
		}
	}
	builtins := strings.Fields("core ctype curl date dom fileinfo filter hash iconv json libxml mbstring openssl pcre pdo phar posix random readline reflection session simplexml sodium spl sqlite3 pdo_sqlite standard tokenizer xml xmlreader xmlwriter zlib")
	deps := map[string][]string{"bcmath": {}, "exif": {}, "gd": {"libpng-dev", "libjpeg62-turbo-dev", "libfreetype6-dev"}, "intl": {"libicu-dev"}, "mysqli": {}, "pcntl": {}, "pdo_mysql": {}, "pdo_pgsql": {"libpq-dev"}, "pgsql": {"libpq-dev"}, "sockets": {}, "soap": {"libxml2-dev"}, "zip": {"libzip-dev"}, "opcache": {}}
	var exts, pkgs []string
	for e := range reqs {
		if slices.Contains(builtins, e) {
			continue
		}
		d, ok := deps[e]
		if !ok {
			return nil, nil, fmt.Errorf("PHP extension %q has no supported build recipe; extend the profile explicitly", e)
		}
		exts = append(exts, e)
		pkgs = append(pkgs, d...)
	}
	sort.Strings(exts)
	sort.Strings(pkgs)
	pkgs = slices.Compact(pkgs)
	return exts, pkgs, nil
}

const phpCollector = `#!/bin/sh
set -eu
mkdir -p /runtime/usr/local/bin /runtime/usr/local/sbin /runtime/usr/local/lib/php /runtime/usr/local/etc/php/conf.d
cp /usr/local/bin/php /runtime/usr/local/bin/php
cp /usr/local/sbin/php-fpm /runtime/usr/local/sbin/php-fpm
cp -a /usr/local/lib/php/extensions /runtime/usr/local/lib/php/
cp -a /usr/local/etc/php/conf.d/. /runtime/usr/local/etc/php/conf.d/
{ ldd /usr/local/bin/php; ldd /usr/local/sbin/php-fpm; find /usr/local/lib/php/extensions -name '*.so' -exec ldd {} \;; } > /tmp/php-libraries
if grep -q 'not found' /tmp/php-libraries; then cat /tmp/php-libraries; exit 1; fi
awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}' /tmp/php-libraries | sort -u > /tmp/php-library-paths
while IFS= read -r lib; do cp -L --parents "$(readlink -f "$lib")" /runtime; done < /tmp/php-library-paths
cp /usr/local/etc/php/php.ini-production /runtime/usr/local/etc/php/php.ini
`

func PHPConfig(c Config) string {
	return fmt.Sprintf(`[global]
daemonize = no
error_log = /proc/self/fd/2
pid = /tmp/php-fpm.pid
[www]
user = 65532
group = 65532
listen = 0.0.0.0:%d
pm = ondemand
pm.max_children = 8
pm.process_idle_timeout = 10s
pm.max_requests = 500
catch_workers_output = yes
decorate_workers_output = no
clear_env = yes
chdir = /app
security.limit_extensions = .php
ping.path = /ping
ping.response = pong
%s
`, c.Port, phpSecretEnv(c))
}
func phpSecretEnv(c Config) string {
	var lines []string
	for k := range c.Env {
		lines = append(lines, "env["+k+"] = $"+k)
	}
	for _, s := range c.Secrets {
		lines = append(lines, "env["+s.Env+"] = $"+s.Env)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

const phpINI = `[PHP]
expose_php = Off
display_errors = Off
log_errors = On
error_log = /proc/self/fd/2
allow_url_include = Off
session.upload_progress.enabled = Off
session.save_path = /tmp
upload_tmp_dir = /tmp
sys_temp_dir = /tmp
memory_limit = 128M
`

func requireNextStandalone(dir string) error {
	for _, f := range []string{"next.config.js", "next.config.mjs", "next.config.ts"} {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err == nil && strings.Contains(string(b), "standalone") {
			return nil
		}
	}
	return fmt.Errorf("Next.js profile requires output: 'standalone' in next.config; set it explicitly (the build also verifies the output)")
}
