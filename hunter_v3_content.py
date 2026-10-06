"""Content discovery — common paths."""
PATHS = [
    "/admin", "/admin/login", "/administrator", "/login", "/signin",
    "/auth", "/dashboard", "/console", "/manage", "/panel",
    "/api", "/api/v1", "/api/v2", "/api-docs",
    "/swagger", "/swagger.json", "/swagger-ui.html", "/openapi.json",
    "/graphql", "/graphiql", "/api/graphql", "/rest",
    "/.env", "/.env.local", "/config", "/config.json",
    "/wp-config.php", "/web.config", "/appsettings.json",
    "/.git/HEAD", "/.git/config", "/.svn/entries",
    "/backup.zip", "/backup.sql", "/db.sql", "/dump.sql",
    "/actuator", "/actuator/health", "/actuator/env",
    "/health", "/healthz", "/readyz", "/metrics",
    "/phpinfo.php", "/info.php", "/debug", "/trace",
    "/status", "/server-status",
    "/robots.txt", "/sitemap.xml", "/humans.txt",
    "/.well-known/security.txt",
    "/wp-admin/", "/wp-login.php", "/phpmyadmin/",
    "/upload", "/uploads/", "/files/", "/download",
    "/search", "/user", "/users", "/profile", "/register",
]
INTERESTING_STATUS = {200, 201, 204, 301, 302, 307, 308, 401, 403}
