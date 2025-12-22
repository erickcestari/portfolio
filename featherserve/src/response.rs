use std::io::{self, Write};

pub struct Response {
    status: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
    gzip: bool,
    cache_control: Option<&'static str>,
}

impl Response {
    pub fn ok(body: Vec<u8>, content_type: &'static str, gzip: bool) -> Self {
        Self {
            status: "200 OK",
            content_type,
            body,
            gzip,
            cache_control: None,
        }
    }

    pub fn not_found(body: Vec<u8>, content_type: &'static str, gzip: bool) -> Self {
        Self {
            status: "404 NOT FOUND",
            content_type,
            body,
            gzip,
            cache_control: None,
        }
    }

    pub fn forbidden(attempted_path: &str) -> Self {
        let body = Self::honeypot_response(attempted_path);
        Self {
            status: "200 OK",
            content_type: "text/plain",
            body,
            gzip: false,
            cache_control: None,
        }
    }

    pub fn with_cache_control(mut self, cache_control: &'static str) -> Self {
        self.cache_control = Some(cache_control);
        self
    }

    pub fn write_to<W: Write>(self, writer: &mut W) -> io::Result<()> {
        let encoding_header = if self.gzip {
            "Content-Encoding: gzip\r\n"
        } else {
            ""
        };

        let cache_header = self
            .cache_control
            .map(|cc| format!("Cache-Control: {}\r\n", cc))
            .unwrap_or_default();

        let header = format!(
            "HTTP/1.1 {}\r\nContent-Length: {}\r\nContent-Type: {}\r\n{}{}\r\n",
            self.status,
            self.body.len(),
            self.content_type,
            encoding_header,
            cache_header,
        );

        writer.write_all(header.as_bytes())?;
        writer.write_all(&self.body)
    }

    fn honeypot_response(path: &str) -> Vec<u8> {
        let lower = path.to_lowercase();

        if lower.contains("etc/passwd") {
            b"root:x:0:0:root:/root:/bin/bash\n\
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\
postgres:x:113:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\n\
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n\
deploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash\n"
                .to_vec()
        } else if lower.contains("etc/shadow") {
            b"root:$6$rounds=656000$YQKe8Y8vN4C7vKFp$xvGm.MXvMKd8z7Q2J9X0KZPqE3wN5yL4xRt2gH6fM9p:19723:0:99999:7:::\n\
ubuntu:$6$rounds=656000$kH7L2m9Pp5N8qR4T$mN3pQ5rF8xS6vY9Z2eK4nH7jM8pL6qR9tS5wV3xB2cD:19723:0:99999:7:::\n\
deploy:!:19723:0:99999:7:::\n"
                .to_vec()
        } else if lower.contains(".env") {
            b"# Database Configuration\n\
DATABASE_URL=postgresql://prod_user:K7mN9pQ2rS5tV8wX@db-prod-1.c9x4h2m5k6n3.us-east-1.rds.amazonaws.com:5432/application_prod\n\
DB_POOL_SIZE=20\n\
\n\
# Application Secrets\n\
SECRET_KEY_BASE=c89f4e3a7b2d1f6e5a8b9c7d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f\n\
JWT_SECRET=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6\n\
\n\
# AWS Credentials\n\
AWS_ACCESS_KEY_ID=AKIAJ7Q4M5X2N8P3R6T9\n\
AWS_SECRET_ACCESS_KEY=Kx7mN9pQ2rS5tV8wX1yZ3aB4cD6eF8gH0iJ2kL4m\n\
AWS_REGION=us-east-1\n\
S3_BUCKET=prod-application-assets-2024\n\
\n\
# Payment Gateway\n\
STRIPE_SECRET_KEY=sk_live_51MkL9pH2e3K4r5T6y7U8v9W0x1Y2z3A4b5C6d7E8f9G0h1I2j3K4l5M6n7O8p9Q\n\
STRIPE_PUBLISHABLE_KEY=pk_live_51MkL9pH2e3K4r5T6y7U8v9W0x1Y2z3A4b5C6d7E8f9G0h1I2j3\n\
\n\
# Third Party APIs\n\
SENDGRID_API_KEY=SG.hX7kM2nP9qR3sT5vW8xY1zA4bC6dE9fG2hI5jK8lM0nO3pQ6rS9tU2vW5xY8zA\n\
TWILIO_ACCOUNT_SID=AC89f4e3a7b2d1f6e5a8b9c7d4e3f2a1b\n\
TWILIO_AUTH_TOKEN=7k2m9p5q8r3s6t9v2w5x8y1z4a7b0c3d\n\
\n\
# Redis\n\
REDIS_URL=redis://:p@ssw0rd123@prod-redis-001.cache.amazonaws.com:6379/0\n\
\n\
# Monitoring\n\
SENTRY_DSN=https://a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6@o123456.ingest.sentry.io/7890123\n"
                .to_vec()
        } else if lower.contains("id_rsa") || lower.contains("ssh") {
            b"-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n\
NhAAAAAwEAAQAAAYEAx7kM2nP9qR3sT5vW8xY1zA4bC6dE9fG2hI5jK8lM0nO3pQ6rS9tU\n\
2vW5xY8zAaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZzAaBbCcDdEe\n\
FfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZzAaBbCcDdEeFfGgHhIiJjKkLlMmNn\n\
OoPpQqRrSsTtUuVvWwXxYyZzAaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWw\n\
XxYyZzAaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZzAaBbCcDdEeFf\n\
GgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZzAAAAAwEAAQAAAYB7kM2nP9qR3sT5vW\n\
8xY1zA4bC6dE9fG2hI5jK8lM0nO3pQ6rS9tU2vW5xY8zAaBbCcDdEeFfGgHhIiJjKkLlMm\n\
NnOoPpQqRrSsTtUuVvWwXxYyZzAaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVv\n\
WwXxYyZzAaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZzAAAAQQDkM2\n\
nP9qR3sT5vW8xY1zA4bC6dE9fG2hI5jK8lM0nO3pQ6rS9tU2vW5xY8zAaBbCcDdEeFfGgH\n\
hIiJjKkLlMmNnAAAAQQDx7kM2nP9qR3sT5vW8xY1zA4bC6dE9fG2hI5jK8lM0nO3pQ6rS9\n\
tU2vW5xY8zAaBbCcDdEeFfGgHhIiJjKkLlMmNnAAAAQQDN2nP9qR3sT5vW8xY1zA4bC6dE\n\
9fG2hI5jK8lM0nO3pQ6rS9tU2vW5xY8zAaBbCcDdEeFfGgHhIiJjKkLlMmNnAAAAE2RlcG\n\
xveUBwcm9kLXNlcnZlcgECAw==\n\
-----END OPENSSH PRIVATE KEY-----\n"
                .to_vec()
        } else if lower.contains("wp-config") || lower.contains("wordpress") {
            b"<?php\n\
/**\n\
 * WordPress Database Configuration\n\
 */\n\
define('DB_NAME', 'wp_production_db');\n\
define('DB_USER', 'wp_admin_2024');\n\
define('DB_PASSWORD', 'Wp#2024!Pr0d@8x9M2nP5q');\n\
define('DB_HOST', 'mysql-prod-1.c9x4h2m5k6n3.us-east-1.rds.amazonaws.com');\n\
define('DB_CHARSET', 'utf8mb4');\n\
define('DB_COLLATE', '');\n\
\n\
/**\n\
 * Authentication Keys and Salts\n\
 */\n\
define('AUTH_KEY',         'k7-M2n!P9q@R3s#T5v$W8x%Y1z^A4b&C6d*E9f(G2h)I5j+K8l=M0n[O3p]Q6r{S9t}');\n\
define('SECURE_AUTH_KEY',  'U2v-W5x!Y8z@A1b#C4d$E7f%G0h^I3j&K6l*M9n(O2p)Q5r+S8t=U1v[W4x]Y7z{A0b}');\n\
define('LOGGED_IN_KEY',    'C3d-E6f!G9h@I2j#K5l$M8n%O1p^Q4r&S7t*U0v(W3x)Y6z+A9b=C2d[E5f]G8h{I1j}');\n\
define('NONCE_KEY',        'K4l-M7n!O0p@Q3r#S6t$U9v%W2x^Y5z&A8b*C1d(E4f)G7h+I0j=K3l[M6n]O9p{Q2r}');\n\
define('AUTH_SALT',        'S5t-U8v!W1x@Y4z#A7b$C0d%E3f^G6h&I9j*K2l(M5n)O8p+Q1r=S4t[U7v]W0x{Y3z}');\n\
define('SECURE_AUTH_SALT', 'A6b-C9d!E2f@G5h#I8j$K1l%M4n^O7p&Q0r*S3t(U6v)W9x+Y2z=A5b[C8d]E1f{G4h}');\n\
define('LOGGED_IN_SALT',   'I7j-K0l!M3n@O6p#Q9r$S2t%U5v^W8x&Y1z*A4b(C7d)E0f+G3h=I6j[K9l]M2n{O5p}');\n\
define('NONCE_SALT',       'Q8r-S1t!U4v@W7x#Y0z$A3b%C6d^E9f&G2h*I5j(K8l)M1n+O4p=Q7r[S0t]U3v{W6x}');\n\
\n\
$table_prefix = 'wp_prod_';\n\
define('WP_DEBUG', false);\n"
                .to_vec()
        } else if lower.contains("proc/self") || lower.contains("/proc/") {
            b"Name:   nginx\n\
Umask:  0022\n\
State:  S (sleeping)\n\
Tgid:   1842\n\
Ngid:   0\n\
Pid:    1842\n\
PPid:   1\n\
TracerPid:      0\n\
Uid:    33      33      33      33\n\
Gid:    33      33      33      33\n\
FDSize: 64\n\
Groups: 33\n\
VmPeak:   892140 kB\n\
VmSize:   892076 kB\n\
VmLck:         0 kB\n\
VmPin:         0 kB\n\
VmHWM:    123456 kB\n\
VmRSS:    121832 kB\n"
                .to_vec()
        } else if lower.contains("flag") || lower.contains("ctf") {
            b"FLAG{th1s_l00ks_r34l_but_1ts_n0t_7ry_h4rd3r}\n\
CTF{c4n0n1c4l1z3_s4v3d_th3_d4y_4g41n}\n\
flag{fake_flag_a7b2c9d1e5f8g3h6i0j4k7l2m9n5o8p1q4r7s0t3u6v9w2x5y8z1}\n"
                .to_vec()
        } else if lower.contains("config") || lower.contains(".conf") {
            b"[server]\n\
host = 0.0.0.0\n\
port = 8080\n\
workers = 4\n\
\n\
[database]\n\
url = postgresql://app_user:P@ssw0rd_2024_Pr0d@db-prod-1.internal:5432/app_db\n\
pool_size = 25\n\
timeout = 30\n\
\n\
[redis]\n\
host = redis-prod.cache.internal\n\
port = 6379\n\
password = R3d1s_P@ss_2024!Secure\n\
db = 0\n\
\n\
[logging]\n\
level = info\n\
file = /var/log/application/app.log\n\
\n\
[security]\n\
secret_key = 4f7e9b2d8c5a1e3f6b9d2c5a8e1f4b7d0c3e6f9b2d5a8c1e4f7b0d3e6f9c2a5b8d1e4f\n\
jwt_expiry = 3600\n\
allowed_origins = api.example.com,app.example.com\n"
                .to_vec()
        } else if lower.contains("aws") || lower.contains("credentials") {
            b"[default]\n\
aws_access_key_id = AKIAJ5M8N3P7Q2R4S6T9\n\
aws_secret_access_key = hX7kM2nP9qR3sT5vW8xY1zA4bC6dE9fG2hI5jK8l\n\
region = us-east-1\n\
output = json\n\
\n\
[production]\n\
aws_access_key_id = AKIAW2X5Y8Z1A3B6C9D2\n\
aws_secret_access_key = mN0pQ3rS6tU9vW2xY5zA8bC1dE4fG7hI0jK3lM6n\n\
region = us-west-2\n\
\n\
[staging]\n\
aws_access_key_id = AKIAE4F7G0H3I6J9K2L5\n\
aws_secret_access_key = oP9qR2sT5uV8wX1yZ4aB7cD0eF3gH6iJ9kL2mN5o\n\
region = us-east-1\n"
                .to_vec()
        } else if lower.contains("docker") || lower.contains("compose") {
            b"version: '3.8'\n\
\n\
services:\n\
  web:\n\
    image: myapp/production:latest\n\
    environment:\n\
      - DATABASE_URL=postgresql://prod_user:Db_P@ss_2024!Secure@postgres:5432/production\n\
      - REDIS_URL=redis://:R3d1s_P@ss@redis:6379/0\n\
      - SECRET_KEY=docker_secret_key_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6\n\
    ports:\n\
      - \"8080:8080\"\n\
\n\
  postgres:\n\
    image: postgres:16\n\
    environment:\n\
      - POSTGRES_PASSWORD=Db_P@ss_2024!Secure\n\
      - POSTGRES_USER=prod_user\n\
      - POSTGRES_DB=production\n"
                .to_vec()
        } else {
            br#"Nice attack, but you're not allowed to do that.
Better luck next time, script kiddie.

     
    _____
   /     \
  | () () |
   \  ^  /
    |||||
    |||||
"#
            .to_vec()
        }
    }
}
