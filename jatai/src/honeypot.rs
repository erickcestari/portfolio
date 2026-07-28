//! The honeypot: paths only an attacker asks for, and the bait they get back.
//!
//! One table drives both halves of the trap, so a pattern can never be
//! recognised without having an answer, or answer without being recognised.
//! First match wins, which is why specific traps are listed before generic
//! ones: `/config/.env` is an env-file hunt, not a config-file hunt.
//!
//! The bait is fabricated. Every credential here is random noise in the right
//! shape, valid nowhere, so a scanner that harvests it spends its time on
//! dead ends instead of on the real internet.

/// What a caught request is answered with.
#[derive(Clone, Copy)]
pub struct Bait {
    pub body: &'static str,
    pub content_type: &'static str,
}

/// How a trap recognises a request.
///
/// Matching is per path segment, never on the raw string. A substring rule
/// would swallow ordinary pages that merely mention the word: `flag` would eat
/// `/blog/feature-flags-in-bitcoin`, and the visitor would get fake credentials
/// instead of the article.
enum Match {
    /// A segment that is this name, with or without a file extension.
    /// `Name(".env")` catches `.env` and `.env.production`, never `envoy`.
    /// Written with an extension it is exact: `Name("web.config")`.
    Name(&'static str),
    /// Any segment carrying this extension. `Ext(".php")` catches `index.php`.
    Ext(&'static str),
    /// Consecutive segments, in order. `Path(&["etc", "passwd"])` catches
    /// `/etc/passwd` and `/../../etc/passwd`, never a page called `passwd`.
    Path(&'static [&'static str]),
}

impl Match {
    fn matches(&self, segments: &[&str]) -> bool {
        match self {
            Match::Name(name) => segments.iter().any(|segment| {
                *segment == *name
                    || segment
                        .strip_prefix(name)
                        .is_some_and(|ext| ext.starts_with('.'))
            }),
            Match::Ext(ext) => segments
                .iter()
                .any(|segment| segment.len() > ext.len() && segment.ends_with(ext)),
            Match::Path(names) => segments.windows(names.len()).any(|window| window == *names),
        }
    }
}

struct Trap {
    patterns: &'static [Match],
    bait: Bait,
}

/// Recognise an attack path and pick its bait.
///
/// Normalisation is deliberately more permissive than serving: extra layers of
/// percent-encoding, backslash separators and capitals are all ways of writing
/// the same request. Lookups elsewhere use the literal path, so a normalised
/// one can never reach a real file.
pub fn bait_for(path: &str) -> Option<Bait> {
    let normalised = normalise(path);
    let segments = segments(&normalised);

    TRAPS
        .iter()
        .find(|trap| trap.patterns.iter().any(|p| p.matches(&segments)))
        .map(|trap| trap.bait)
}

fn normalise(path: &str) -> String {
    crate::request::fully_decode(path)
        .replace('\\', "/")
        .to_lowercase()
}

fn segments(normalised: &str) -> Vec<&str> {
    normalised.split('/').filter(|s| !s.is_empty()).collect()
}

const TEXT: &str = "text/plain";
const HTML: &str = "text/html";
const JSON: &str = "application/json";

const TRAPS: &[Trap] = &[
    trap(&[Match::Path(&["etc", "passwd"])], TEXT, PASSWD),
    trap(&[Match::Path(&["etc", "shadow"])], TEXT, SHADOW),
    trap(&[Match::Name(".env")], TEXT, DOTENV),
    trap(&[Match::Name("authorized_keys")], TEXT, AUTHORIZED_KEYS),
    trap(
        &[
            Match::Name("id_rsa"),
            Match::Name("id_dsa"),
            Match::Name("id_ecdsa"),
            Match::Name("id_ed25519"),
            Match::Name(".ssh"),
            Match::Name("ssh"),
        ],
        TEXT,
        SSH_KEY,
    ),
    trap(
        &[Match::Name(".git-credentials"), Match::Name(".netrc")],
        TEXT,
        GIT_CREDENTIALS,
    ),
    trap(
        &[Match::Name(".git"), Match::Name(".gitconfig")],
        TEXT,
        GIT_CONFIG,
    ),
    trap(&[Match::Name(".svn")], TEXT, SVN_ENTRIES),
    trap(
        &[Match::Name("wp-login"), Match::Name("wp-admin")],
        HTML,
        WP_LOGIN,
    ),
    trap(
        &[Match::Name("wp-config"), Match::Name("wordpress")],
        TEXT,
        WP_CONFIG,
    ),
    trap(
        &[Match::Name("phpmyadmin"), Match::Name("pma")],
        HTML,
        PHPMYADMIN,
    ),
    trap(
        &[Match::Name("phpinfo"), Match::Name("info.php")],
        HTML,
        PHPINFO,
    ),
    trap(&[Match::Name("proc")], TEXT, PROC_STATUS),
    trap(&[Match::Name(".htpasswd")], TEXT, HTPASSWD),
    trap(&[Match::Name(".htaccess")], TEXT, HTACCESS),
    trap(
        &[Match::Name(".bash_history"), Match::Name(".zsh_history")],
        TEXT,
        BASH_HISTORY,
    ),
    trap(&[Match::Name(".npmrc")], TEXT, NPMRC),
    trap(&[Match::Name(".pypirc")], TEXT, PYPIRC),
    trap(
        &[Match::Ext(".sql"), Match::Name("mysqldump")],
        TEXT,
        SQL_DUMP,
    ),
    trap(&[Match::Name("actuator")], JSON, ACTUATOR_ENV),
    trap(
        &[Match::Name("server-status"), Match::Name("server-info")],
        HTML,
        SERVER_STATUS,
    ),
    trap(
        &[
            Match::Name("meta-data"),
            Match::Name("user-data"),
            Match::Name("169.254.169.254"),
        ],
        JSON,
        IMDS_CREDENTIALS,
    ),
    trap(
        &[Match::Ext(".tfstate"), Match::Name("terraform")],
        JSON,
        TFSTATE,
    ),
    trap(
        &[
            Match::Name("kubeconfig"),
            Match::Name(".kube"),
            Match::Path(&["kube", "config"]),
        ],
        TEXT,
        KUBECONFIG,
    ),
    trap(&[Match::Name("web.config")], TEXT, WEB_CONFIG),
    trap(&[Match::Name("flag"), Match::Name("ctf")], TEXT, FLAGS),
    trap(
        &[
            Match::Name(".aws"),
            Match::Name("aws"),
            Match::Name("credentials"),
        ],
        TEXT,
        AWS_CREDENTIALS,
    ),
    trap(
        &[
            Match::Name("docker-compose"),
            Match::Name("dockerfile"),
            Match::Name(".dockerignore"),
            Match::Name("docker"),
        ],
        TEXT,
        DOCKER_COMPOSE,
    ),
    trap(
        &[
            Match::Name("config"),
            Match::Name("configuration"),
            Match::Ext(".conf"),
            Match::Ext(".ini"),
        ],
        TEXT,
        APP_CONFIG,
    ),
    // Anything else that only an attacker would type: no plausible file to
    // fake, so say so.
    trap(&[Match::Name(".."), Match::Ext(".php")], TEXT, TAUNT),
];

const fn trap(patterns: &'static [Match], content_type: &'static str, body: &'static str) -> Trap {
    Trap {
        patterns,
        bait: Bait { body, content_type },
    }
}

const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
bin:x:2:2:bin:/bin:/usr/sbin/nologin\n\
sys:x:3:3:sys:/dev:/usr/sbin/nologin\n\
sync:x:4:65534:sync:/bin:/bin/sync\n\
games:x:5:60:games:/usr/games:/usr/sbin/nologin\n\
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n\
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n\
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n\
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n\
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n\
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n\
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n\
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n\
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n\
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin\n\
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n\
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\n\
messagebus:x:103:105::/nonexistent:/usr/sbin/nologin\n\
systemd-timesync:x:104:106:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\n\
syslog:x:105:111::/nonexistent:/usr/sbin/nologin\n\
uuidd:x:106:112::/run/uuidd:/usr/sbin/nologin\n\
tcpdump:x:107:113::/nonexistent:/usr/sbin/nologin\n\
sshd:x:108:65534::/run/sshd:/usr/sbin/nologin\n\
pollinate:x:109:1::/var/cache/pollinate:/bin/false\n\
landscape:x:110:114::/var/lib/landscape:/usr/sbin/nologin\n\
postgres:x:111:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\n\
redis:x:112:118::/var/lib/redis:/usr/sbin/nologin\n\
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false\n\
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n\
deploy:x:1001:1001:Deploy User,,,:/home/deploy:/bin/bash\n";

const SHADOW: &str = "root:$y$j9T$T0D8jVIrqN1hd9syOjBmYj$Fltwx0DfPZDZokx01MsfiL8PW951DKyhlJsxg0OJ.:19847:0:99999:7:::\n\
daemon:*:19835:0:99999:7:::\n\
bin:*:19835:0:99999:7:::\n\
sys:*:19835:0:99999:7:::\n\
sync:*:19835:0:99999:7:::\n\
games:*:19835:0:99999:7:::\n\
man:*:19835:0:99999:7:::\n\
www-data:*:19835:0:99999:7:::\n\
backup:*:19835:0:99999:7:::\n\
nobody:*:19835:0:99999:7:::\n\
systemd-network:!*:19835::::::\n\
systemd-resolve:!*:19835::::::\n\
messagebus:!:19835::::::\n\
syslog:!:19835::::::\n\
sshd:!:19841::::::\n\
postgres:$y$j9T$Bu1sDhGknatuRyC7Mmj2Y5$KBjq6epj89WddJZwtQFI12OqqvqQIjAamjSkjfK.:19844:0:99999:7:::\n\
redis:!:19844::::::\n\
ubuntu:$y$j9T$SkNLKkfXhHjOGFQPvqzobP$26Hh92ygu4Swmk46eqqxaYuJ3nE3BrYqdKejKLiR.:19851:0:99999:7:::\n\
deploy:$y$j9T$nAh7Tmq9tHSVPArHXekwVM$6cYePZpn9Ud3LEUnYgdd2Xl4VBN6BddTkm5hgKZ.:19849:0:99999:7:::\n";

const DOTENV: &str = "APP_NAME=acme-payments\n\
APP_ENV=production\n\
APP_DEBUG=false\n\
APP_URL=https://api.acme-internal.com\n\
\n\
# Database\n\
DATABASE_URL=postgresql://payments_prod:xK7mN2pQ9rS5tV8w@db-prod-01.c9x4h2m5k6n3.us-east-1.rds.amazonaws.com:5432/payments\n\
DB_POOL_SIZE=25\n\
DB_SSL_MODE=require\n\
\n\
# Cache and queue\n\
REDIS_URL=redis://:R3d1sPr0d2024Secure@prod-redis-001.c9x4h2.ng.0001.use1.cache.amazonaws.com:6379/0\n\
QUEUE_CONNECTION=redis\n\
\n\
# Application secrets\n\
SECRET_KEY_BASE=5cc207f8e44fa3f20763ace517a0b03a1833eb95b385661bdede0bc27fa009be\n\
JWT_SECRET=659758927b438766790f27089964f08768e35ee9148bf3b479e5df4b1223800c\n\
SESSION_LIFETIME=120\n\
\n\
# AWS\n\
AWS_ACCESS_KEY_ID=AKIA4XZQ7YWNP2K6R3TF\n\
AWS_SECRET_ACCESS_KEY=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\n\
AWS_DEFAULT_REGION=us-east-1\n\
AWS_BUCKET=acme-payments-prod-assets\n\
\n\
# Stripe\n\
STRIPE_KEY=pk_live_51NxK2mHZq8VbRtY4wLpGdCfEjMnQaSvTuXyZ3B7c\n\
STRIPE_SECRET=sk_live_51NxK2mHZq8VbRtY4wLpGdCfEjMnQaSvTuXyZ3B7c9D2eF5gH8jK1lM4n\n\
STRIPE_WEBHOOK_SECRET=whsec_dee1be26265143dc4834d273d9b569b95b06de16\n\
\n\
# Mail\n\
MAIL_MAILER=smtp\n\
MAIL_HOST=email-smtp.us-east-1.amazonaws.com\n\
MAIL_PORT=587\n\
MAIL_USERNAME=AKIA6TDPQ4XNVK8MR2WY\n\
MAIL_PASSWORD=aJ2mV2zqwm59Ddn7jI00kLa99bhvRF8THy2Cq1r8\n\
SENDGRID_API_KEY=SG.1K7pxPWeILf8N6gkbER2WO.ECCxIKa5rHWWcLWTuESvyjS9xrUgUTtutbX652Gp5D\n\
\n\
# Third party\n\
GITHUB_TOKEN=ghp_v4M5a0fYACLmGYHy2KwPSaJErszbIroEVh1K\n\
SLACK_BOT_TOKEN=xoxb-2847193056-4917283640-tN0pEVfzl2TVRgHmHFHTZgjo\n\
OPENAI_API_KEY=sk-proj-Y7IiFNnyg7JQfE5QTDxROia8HwPWsXHBLcI09RVOpsrFCjSC\n\
TWILIO_ACCOUNT_SID=AC85a4e4d181764db294a1032198abee1c\n\
TWILIO_AUTH_TOKEN=f3f0e1dedf3b5669cf5514bebff347ee\n\
SENTRY_DSN=https://900e1acae780c1716a907ef94c02840b@o447951.ingest.sentry.io/4504218472\n";

const AUTHORIZED_KEYS: &str = "# Managed by Ansible, do not edit by hand\n\
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH2vK8mQpR4tN7wXzL3bYcE9fG1jH5kM8nP0qS6uV2xA deploy@ci-runner-01\n\
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dR2fT5hK8mN1pQ4sV7wY0zC3eF6gJ9kL2nM5oP8rB ops@bastion-prod\n\
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDT0ToaFJ2CI6m3s8X8N1smg6JfrhXpnuMzWpagWDVEoQ28SbRf2rW32eqTEafnFGbtmJsnSgdRL7zTm8zt0gwqtCSlueQz0P550Lqfuj0GExeTWPYHMxHn3tlm71lOWOKXlikWpoQWY6DAEg0W4vrRdoPGu5NrVuL93Gcb2NkIFqVuzVOYqYh4fcr43GHorM76C2x33p0MPUZgfKrJWPsEuS98ZyNsnvjBXk7KVWkmqGAsZYWlJW76rajTf1SeIyxh1YNv4TzHg1ic4T ubuntu@jump-host\n";

const SSH_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n\
NhAAAAAwEAAQAAAYEA0ToaFJ2CI6m3s8X8N1smg6JfrhXpnuMzWpagWDVEoQ28SbRf2rW3\n\
2eqTEafnFGbtmJsnSgdRL7zTm8zt0gwqtCSlueQz0P550Lqfu+j0GEx/eTWPYHMxHn3tlm\n\
71lOWOKXlikWpoQWY6DAEg0W4vrRdoPG+u5NrV/uL93Gcb2NkIFqVuzVOYqYh4fcr43GHo\n\
rM76C2x33p0MPUZgfKrJWPsEuS98ZyNsn+vjBXk7KVWk+mq/GAs+ZYW/lJW76rajTf1SeI\n\
yx+h1YNv4TzHg1ic4TQdoYDYD/F2ROP+JAYcY9rFbOgQzwh2LVNnEJ9TDHisyfVoUoRlb+\n\
+nCS5VKhLdexBkMz2dQwp0k27WeL5t0IFmPypMROyd3Y5RudnPHMeP9/Gz0BB/5VfOn3b2\n\
kA/3novqsSmLL933AVtVDaRYLMaN7jOLF/sUDtc0ko/zerCIFD7kjthdHFQrRb1roZ8/ms\n\
WcnHZAM54wAUlUfUap9rgEsJ0zB8Y/ztxPSdXkpLRD+CtimMkgH4WAhSZSgKaVkyS0Lc0b\n\
Ufmzz/4+ESxGfhiGWQhBPd7q34/Z6Pie78UXIIt97BhJ/K0UFT7LF5RYYIEuqybyn4n39+\n\
tD17xlNCyM4IdlljTzqXascbefV9vqRiuW5EVLPA5j3gHQP8SmxkSE8epcj+j3osqp+H0p\n\
xWgIcsKHMnln+mOGlzHzAB5dnrs8GJW/+j8lykkmVpftQpeDZ0YTRybnVz1PnbzEM9GbCt\n\
zsOmcO5P/Sc75CPiLQmE9SyunMIzYefuJlecVlClZgOn+gvLX5+hyPGNvposgjJIqD4bOh\n\
hs8tbtSXeCD9ndwE5+GVEfaXMBu17K5MOp3t/v4R4/+Uy0jbUgQWUh2ZGq4VB65HPfowts\n\
BVCuyYrdLyEYYcvsjcvMTLEmPx0HojlIK5GAOR8ILwAAAAAEbm9uZQECAwQFBgcICQoLDA\n\
0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BB\n\
QkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dX\n\
Z3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmq\n\
q6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t\n\
/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+foAAAATZGVwbG95QGNpLXJ1bm5lci0wMQEC\n\
-----END OPENSSH PRIVATE KEY-----\n";

const GIT_CREDENTIALS: &str =
    "https://deploy-bot:ghp_v4M5a0fYACLmGYHy2KwPSaJErszbIroEVh1K@github.com\n\
https://acme-ci:glpat-tN0pEVfzl2TVRgHmHFHT@gitlab.acme-internal.com\n";

const GIT_CONFIG: &str = "[core]\n\
\trepositoryformatversion = 0\n\
\tfilemode = true\n\
\tbare = false\n\
\tlogallrefupdates = true\n\
[remote \"origin\"]\n\
\turl = https://deploy-bot:ghp_v4M5a0fYACLmGYHy2KwPSaJErszbIroEVh1K@github.com/acme-internal/payments-api.git\n\
\tfetch = +refs/heads/*:refs/remotes/origin/*\n\
[branch \"main\"]\n\
\tremote = origin\n\
\tmerge = refs/heads/main\n\
[branch \"release/2024.11\"]\n\
\tremote = origin\n\
\tmerge = refs/heads/release/2024.11\n\
[user]\n\
\tname = CI Deploy\n\
\temail = deploy@acme-internal.com\n";

const SVN_ENTRIES: &str = "10\n\
\n\
dir\n\
48213\n\
https://svn.acme-internal.com/repos/payments/trunk\n\
https://svn.acme-internal.com/repos/payments\n\
\n\
\n\
2024-09-14T08:21:47.184290Z\n\
48211\n\
jhalpert\n\
svn:special svn:externals svn:needs-lock\n";

const WP_LOGIN: &str = "<!DOCTYPE html>\n\
<html lang=\"en-US\">\n\
<head>\n\
<meta charset=\"UTF-8\" />\n\
<title>Log In &lsaquo; Acme Blog &#8212; WordPress</title>\n\
<link rel=\"stylesheet\" href=\"/wp-admin/css/login.min.css?ver=6.4.2\" media=\"all\" />\n\
</head>\n\
<body class=\"login no-js login-action-login wp-core-ui\">\n\
<div id=\"login\">\n\
\t<h1><a href=\"https://wordpress.org/\">Powered by WordPress</a></h1>\n\
\t<form name=\"loginform\" id=\"loginform\" action=\"/wp-login.php\" method=\"post\">\n\
\t\t<p><label for=\"user_login\">Username or Email Address</label>\n\
\t\t<input type=\"text\" name=\"log\" id=\"user_login\" class=\"input\" value=\"\" size=\"20\" /></p>\n\
\t\t<p><label for=\"user_pass\">Password</label>\n\
\t\t<input type=\"password\" name=\"pwd\" id=\"user_pass\" class=\"input\" value=\"\" size=\"20\" /></p>\n\
\t\t<p class=\"submit\"><input type=\"submit\" name=\"wp-submit\" id=\"wp-submit\" class=\"button button-primary button-large\" value=\"Log In\" /></p>\n\
\t</form>\n\
</div>\n\
</body>\n\
</html>\n";

const WP_CONFIG: &str = "<?php\n\
/**\n\
 * The base configuration for WordPress\n\
 *\n\
 * @package WordPress\n\
 */\n\
\n\
// ** Database settings ** //\n\
define( 'DB_NAME', 'acme_wp_prod' );\n\
define( 'DB_USER', 'wp_admin' );\n\
define( 'DB_PASSWORD', 'Wp#2024!Pr0d@8x9M2nP5q' );\n\
define( 'DB_HOST', 'mysql-prod-01.c9x4h2m5k6n3.us-east-1.rds.amazonaws.com' );\n\
define( 'DB_CHARSET', 'utf8mb4' );\n\
define( 'DB_COLLATE', '' );\n\
\n\
/**#@+\n\
 * Authentication unique keys and salts.\n\
 */\n\
define( 'AUTH_KEY',         'nezMQoYQaI5mpEz9CB6e5eU1rdPY2bm9rnNX6dSARpoMstfJ53DSMVaM1PJZ4JO' );\n\
define( 'SECURE_AUTH_KEY',  'Tm1elcuVHvSn2A1DfOECuxsFPOZpo8wIHc7BIZZBW1dLEeTgEh6MpadDO0Wj' );\n\
define( 'LOGGED_IN_KEY',    'UMA8WjLIulaZ0VWxDmlVYtMyI31aM1HLLWqDHd4v8jLnIiWg5QMzVZ6LxXc' );\n\
define( 'NONCE_KEY',        'YfifZBklKGvELEB5mm7RrBKaR5dxEnB57MF1qqOHNGihI5WUG4hfU7Ar7dl' );\n\
define( 'AUTH_SALT',        'FjkHvj3vhqi93whkx14RG1fyOsxc5y4nl4Dktuo57XtEWbJ7y1wAShVGa9tyDh' );\n\
define( 'SECURE_AUTH_SALT', 'kttMcFX4RQi6bjXcDa27PSZsi6JIujrmAnTYRJ7TgHLweFalR5EOEvCD7BmmgG4' );\n\
define( 'LOGGED_IN_SALT',   'SbNj3w81ezh9XnW8FFNQ9ClmHaeBb49KISd0xE1lFZYbVMpUnM59ofNqAtacEZJ' );\n\
define( 'NONCE_SALT',       'IVg1n3BKHzjrG3qxEFeggLbdQ4FVveF9hFYsUzixkQbbGyldUTkCd21PMVLHneK' );\n\
/**#@-*/\n\
\n\
$table_prefix = 'wp_';\n\
\n\
define( 'WP_DEBUG', false );\n\
define( 'DISALLOW_FILE_EDIT', true );\n\
define( 'WP_MEMORY_LIMIT', '256M' );\n\
\n\
/* That's all, stop editing! Happy publishing. */\n\
\n\
if ( ! defined( 'ABSPATH' ) ) {\n\
\tdefine( 'ABSPATH', __DIR__ . '/' );\n\
}\n\
\n\
require_once ABSPATH . 'wp-settings.php';\n";

const PHPMYADMIN: &str = "<!DOCTYPE HTML>\n\
<html lang=\"en\" dir=\"ltr\">\n\
<head>\n\
<meta charset=\"utf-8\" />\n\
<title>phpMyAdmin</title>\n\
<link rel=\"stylesheet\" type=\"text/css\" href=\"/phpmyadmin/themes/pmahomme/css/theme.css\" />\n\
</head>\n\
<body class=\"loginform\">\n\
<div class=\"container\">\n\
<a href=\"https://www.phpmyadmin.net/\" class=\"logo\">phpMyAdmin 5.2.1</a>\n\
<form method=\"post\" action=\"/phpmyadmin/index.php?route=/\" name=\"login_form\" class=\"login\">\n\
\t<label for=\"input_username\">Username:</label>\n\
\t<input type=\"text\" name=\"pma_username\" id=\"input_username\" value=\"\" />\n\
\t<label for=\"input_password\">Password:</label>\n\
\t<input type=\"password\" name=\"pma_password\" id=\"input_password\" value=\"\" />\n\
\t<input type=\"hidden\" name=\"server\" value=\"1\" />\n\
\t<input type=\"submit\" name=\"input_go\" id=\"input_go\" value=\"Go\" />\n\
</form>\n\
</div>\n\
</body>\n\
</html>\n";

const PHPINFO: &str = "<!DOCTYPE html>\n\
<html><head><title>phpinfo()</title></head>\n\
<body class=\"phpinfo\">\n\
<h1 class=\"p\">PHP Version 8.1.2-1ubuntu2.14</h1>\n\
<table>\n\
<tr><td class=\"e\">System </td><td class=\"v\">Linux web-prod-01 5.15.0-89-generic #99-Ubuntu SMP x86_64 </td></tr>\n\
<tr><td class=\"e\">Server API </td><td class=\"v\">FPM/FastCGI </td></tr>\n\
<tr><td class=\"e\">Loaded Configuration File </td><td class=\"v\">/etc/php/8.1/fpm/php.ini </td></tr>\n\
<tr><td class=\"e\">DOCUMENT_ROOT </td><td class=\"v\">/var/www/acme/public </td></tr>\n\
<tr><td class=\"e\">disable_functions </td><td class=\"v\">no value </td></tr>\n\
<tr><td class=\"e\">allow_url_include </td><td class=\"v\">Off </td></tr>\n\
<tr><td class=\"e\">open_basedir </td><td class=\"v\">no value </td></tr>\n\
<tr><td class=\"e\">DB_PASSWORD </td><td class=\"v\">Wp#2024!Pr0d@8x9M2nP5q </td></tr>\n\
</table>\n\
</body></html>\n";

const PROC_STATUS: &str = "Name:\tnginx\n\
Umask:\t0022\n\
State:\tS (sleeping)\n\
Tgid:\t1842\n\
Ngid:\t0\n\
Pid:\t1842\n\
PPid:\t1\n\
TracerPid:\t0\n\
Uid:\t33\t33\t33\t33\n\
Gid:\t33\t33\t33\t33\n\
FDSize:\t128\n\
Groups:\t33\n\
NStgid:\t1842\n\
NSpid:\t1842\n\
NSpgid:\t1841\n\
NSsid:\t1841\n\
VmPeak:\t  892140 kB\n\
VmSize:\t  892076 kB\n\
VmLck:\t       0 kB\n\
VmPin:\t       0 kB\n\
VmHWM:\t  123456 kB\n\
VmRSS:\t  121832 kB\n\
RssAnon:\t   98304 kB\n\
RssFile:\t   23528 kB\n\
RssShmem:\t       0 kB\n\
VmData:\t  104856 kB\n\
VmStk:\t     132 kB\n\
VmExe:\t    1204 kB\n\
VmLib:\t   14328 kB\n\
VmPTE:\t     368 kB\n\
VmSwap:\t       0 kB\n\
Threads:\t4\n\
SigQ:\t0/31196\n\
SigPnd:\t0000000000000000\n\
ShdPnd:\t0000000000000000\n\
SigBlk:\t0000000000000000\n\
SigIgn:\t0000000040001000\n\
SigCgt:\t0000000198016a07\n\
CapInh:\t0000000000000000\n\
CapPrm:\t0000000000000000\n\
CapEff:\t0000000000000000\n\
CapBnd:\t000001ffffffffff\n\
Seccomp:\t0\n\
Cpus_allowed_list:\t0-3\n\
Mems_allowed_list:\t0\n\
voluntary_ctxt_switches:\t18294\n\
nonvoluntary_ctxt_switches:\t412\n";

const HTPASSWD: &str = "admin:$apr1$Fj8kL2mN$q7Yx3Pd2VmL9sT6hRw8Fb0\n\
deploy:$apr1$T9vW1zB4$c03nKq7YxPd2VmL9sT6hR1\n\
monitoring:$2y$10$IVg1n3BKHzjrG3qxEFeggLbdQ4FVveF9hFYsUzixkQbbGyldUTkCd\n\
backup:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n";

const HTACCESS: &str = "RewriteEngine On\n\
RewriteBase /\n\
RewriteRule ^index\\.php$ - [L]\n\
RewriteCond %{REQUEST_FILENAME} !-f\n\
RewriteCond %{REQUEST_FILENAME} !-d\n\
RewriteRule . /index.php [L]\n\
\n\
<Files \"config.inc.php\">\n\
\tRequire all denied\n\
</Files>\n\
\n\
AuthType Basic\n\
AuthName \"Staging Area\"\n\
AuthUserFile /var/www/acme/.htpasswd\n\
Require valid-user\n\
\n\
php_value upload_max_filesize 64M\n\
php_value post_max_size 64M\n";

const BASH_HISTORY: &str = "cd /var/www/acme\n\
git pull origin main\n\
sudo systemctl restart nginx\n\
psql -h db-prod-01.c9x4h2m5k6n3.us-east-1.rds.amazonaws.com -U payments_prod -d payments\n\
export PGPASSWORD='xK7mN2pQ9rS5tV8w'\n\
pg_dump payments > /tmp/payments-2024-11-18.sql\n\
aws s3 cp /tmp/payments-2024-11-18.sql s3://acme-payments-prod-assets/backups/\n\
mysql -u wp_admin -p'Wp#2024!Pr0d@8x9M2nP5q' acme_wp_prod\n\
ssh -i ~/.ssh/id_rsa deploy@10.0.3.14\n\
docker compose -f /srv/acme/docker-compose.yml up -d\n\
curl -H \"Authorization: Bearer ghp_v4M5a0fYACLmGYHy2KwPSaJErszbIroEVh1K\" https://api.github.com/user\n\
history -c\n";

const NPMRC: &str = "//registry.npmjs.org/:_authToken=npm_lhKECWHWq0zXIVFAod1fGSBHKujYz4jBsfAi\n\
//npm.pkg.github.com/:_authToken=ghp_av55zyFFlxV6xWaIA5RQEUtjlnuFFdNqTZnm\n\
@acme-internal:registry=https://npm.pkg.github.com\n\
always-auth=true\n\
engine-strict=true\n";

const PYPIRC: &str = "[distutils]\n\
index-servers =\n\
    pypi\n\
    acme-internal\n\
\n\
[pypi]\n\
username = __token__\n\
password = pypi-AgEIcHlwaS5vcmcCJDk3ZTIxNGE4LTRiM2QtNGYxYS1hZTgzLTZkOWM0MmYxYjJhMwACKlszLCI5\n\
\n\
[acme-internal]\n\
repository = https://pypi.acme-internal.com/simple\n\
username = ci-publisher\n\
password = N93L1E0TLN4j7CxKJGBjGfUGDHEWC83vUaZDb\n";

const SQL_DUMP: &str = "-- MySQL dump 10.13  Distrib 8.0.35, for Linux (x86_64)\n\
--\n\
-- Host: mysql-prod-01    Database: acme_wp_prod\n\
-- ------------------------------------------------------\n\
-- Server version\t8.0.35-0ubuntu0.22.04.1\n\
\n\
/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;\n\
/*!40103 SET TIME_ZONE='+00:00' */;\n\
\n\
DROP TABLE IF EXISTS `users`;\n\
CREATE TABLE `users` (\n\
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,\n\
  `email` varchar(255) NOT NULL,\n\
  `password_hash` varchar(255) NOT NULL,\n\
  `api_token` varchar(64) DEFAULT NULL,\n\
  `role` varchar(32) NOT NULL DEFAULT 'user',\n\
  `created_at` timestamp NULL DEFAULT NULL,\n\
  PRIMARY KEY (`id`),\n\
  UNIQUE KEY `users_email_unique` (`email`)\n\
) ENGINE=InnoDB AUTO_INCREMENT=8412 DEFAULT CHARSET=utf8mb4;\n\
\n\
LOCK TABLES `users` WRITE;\n\
INSERT INTO `users` VALUES\n\
(1,'admin@acme-internal.com','$2y$10$Tm1elcuVHvSn2A1DfOECuxsFPOZpo8wIHc7BIZZBW1dLEeTgEh6Mp','5cc207f8e44fa3f20763ace517a0b03a','admin','2021-03-04 09:12:44'),\n\
(2,'ops@acme-internal.com','$2y$10$UMA8WjLIulaZ0VWxDmlVYtMyI31aM1HLLWqDHd4v8jLnIiWg5QMzV','659758927b438766790f27089964f087','admin','2021-06-18 14:03:21'),\n\
(3,'jhalpert@acme-internal.com','$2y$10$YfifZBklKGvELEB5mm7RrBKaR5dxEnB57MF1qqOHNGihI5WUG4hfU','dee1be26265143dc4834d273d9b569b9','user','2022-01-27 11:47:09');\n\
UNLOCK TABLES;\n\
\n\
-- Dump completed on 2024-11-18 03:15:22\n";

const ACTUATOR_ENV: &str = "{\n\
  \"activeProfiles\": [\"production\"],\n\
  \"propertySources\": [\n\
    {\n\
      \"name\": \"systemEnvironment\",\n\
      \"properties\": {\n\
        \"SPRING_DATASOURCE_URL\": {\"value\": \"jdbc:postgresql://db-prod-01.internal:5432/payments\"},\n\
        \"SPRING_DATASOURCE_USERNAME\": {\"value\": \"payments_prod\"},\n\
        \"SPRING_DATASOURCE_PASSWORD\": {\"value\": \"xK7mN2pQ9rS5tV8w\"},\n\
        \"AWS_ACCESS_KEY_ID\": {\"value\": \"AKIA4XZQ7YWNP2K6R3TF\"},\n\
        \"AWS_SECRET_ACCESS_KEY\": {\"value\": \"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\"},\n\
        \"JWT_SIGNING_KEY\": {\"value\": \"659758927b438766790f27089964f08768e35ee9148bf3b479e5df4b1223800c\"}\n\
      }\n\
    },\n\
    {\n\
      \"name\": \"applicationConfig: [classpath:/application-production.yml]\",\n\
      \"properties\": {\n\
        \"management.endpoints.web.exposure.include\": {\"value\": \"*\"},\n\
        \"server.port\": {\"value\": 8080}\n\
      }\n\
    }\n\
  ]\n\
}\n";

const SERVER_STATUS: &str = "<!DOCTYPE html>\n\
<html><head><title>Apache Status</title></head>\n\
<body><h1>Apache Server Status for web-prod-01.acme-internal.com</h1>\n\
<dl><dt>Server Version: Apache/2.4.52 (Ubuntu) OpenSSL/3.0.2</dt>\n\
<dt>Server Built: 2024-10-08T12:41:19</dt></dl><hr />\n\
<dl>\n\
<dt>Current Time: Monday, 18-Nov-2024 03:22:41 UTC</dt>\n\
<dt>Restart Time: Sunday, 10-Nov-2024 02:14:07 UTC</dt>\n\
<dt>Server uptime: 8 days 1 hour 8 minutes</dt>\n\
<dt>Total accesses: 4128377 - Total Traffic: 92.4 GB</dt>\n\
<dt>12 requests currently being processed, 38 idle workers</dt>\n\
</dl>\n\
<table border=\"0\"><tr><th>Srv</th><th>PID</th><th>VHost</th><th>Request</th></tr>\n\
<tr><td>0-0</td><td>1842</td><td>api.acme-internal.com</td><td>POST /v1/payments/charge HTTP/1.1</td></tr>\n\
<tr><td>0-1</td><td>1843</td><td>admin.acme-internal.com</td><td>GET /admin/users?token=5cc207f8e44fa3f2 HTTP/1.1</td></tr>\n\
<tr><td>0-2</td><td>1844</td><td>api.acme-internal.com</td><td>GET /internal/health HTTP/1.1</td></tr>\n\
</table>\n\
</body></html>\n";

const IMDS_CREDENTIALS: &str = "{\n\
  \"Code\": \"Success\",\n\
  \"LastUpdated\": \"2024-11-18T02:58:14Z\",\n\
  \"Type\": \"AWS-HMAC\",\n\
  \"AccessKeyId\": \"ASIA4XZQ7YWNRT8PL2VK\",\n\
  \"SecretAccessKey\": \"E2FSUrdXzjxmfWHqSBYQkPjBxyUl40guFtMiRkRs\",\n\
  \"Token\": \"IQoJb3JpZ2luX2VjEJr//////////wEaCXVzLWVhc3QtMSJHMEUCIQDkttMcFX4RQi6bjXcDa27PSZsi6JIujrmAnTYRJ7TgHLweFalR5EOEvCD7BmmgG4CIC9SbNj3w81ezh9XnW8FFNQ9ClmHaeBb49KISd0xE1lFZYbVMpUnM59ofNqAtacEZJ\",\n\
  \"Expiration\": \"2024-11-18T09:12:47Z\"\n\
}\n";

const TFSTATE: &str = "{\n\
  \"version\": 4,\n\
  \"terraform_version\": \"1.6.4\",\n\
  \"serial\": 187,\n\
  \"lineage\": \"8f2b41c7-6d93-4a15-b8e2-0c37fa951d64\",\n\
  \"outputs\": {\n\
    \"db_password\": {\"value\": \"xK7mN2pQ9rS5tV8w\", \"type\": \"string\", \"sensitive\": true},\n\
    \"rds_endpoint\": {\"value\": \"db-prod-01.c9x4h2m5k6n3.us-east-1.rds.amazonaws.com:5432\", \"type\": \"string\"}\n\
  },\n\
  \"resources\": [\n\
    {\n\
      \"mode\": \"managed\",\n\
      \"type\": \"aws_iam_access_key\",\n\
      \"name\": \"ci_deploy\",\n\
      \"instances\": [\n\
        {\n\
          \"attributes\": {\n\
            \"id\": \"AKIA4XZQ7YWNP2K6R3TF\",\n\
            \"secret\": \"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\",\n\
            \"user\": \"ci-deploy\"\n\
          }\n\
        }\n\
      ]\n\
    }\n\
  ]\n\
}\n";

const KUBECONFIG: &str = "apiVersion: v1\n\
kind: Config\n\
current-context: prod-us-east-1\n\
clusters:\n\
- cluster:\n\
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUN5RENDQWJDZ0F3SUJBZ0lCQURBTkJna3E=\n\
    server: https://A1B2C3D4E5F6G7H8.gr7.us-east-1.eks.amazonaws.com\n\
  name: prod-us-east-1\n\
contexts:\n\
- context:\n\
    cluster: prod-us-east-1\n\
    namespace: payments\n\
    user: ci-deploy\n\
  name: prod-us-east-1\n\
users:\n\
- name: ci-deploy\n\
  user:\n\
    token: eyJhbGciOiJSUzI1NiIsImtpZCI6IjJiVkVNeWNzSTlHSnlacEc2Qk1xN2NNNGptdFRNNWFGZlhzU1UifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50In0.1K7pxPWeILf8N6gkbER2WOECCxIKa5rHWWcLW\n";

const WEB_CONFIG: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<configuration>\n\
  <connectionStrings>\n\
    <add name=\"AcmeDb\" connectionString=\"Server=sql-prod-01.acme-internal.com;Database=Payments;User Id=sa;Password=Pr0d$ql!2024#Acme;\" providerName=\"System.Data.SqlClient\" />\n\
  </connectionStrings>\n\
  <appSettings>\n\
    <add key=\"MachineKey\" value=\"5cc207f8e44fa3f20763ace517a0b03a1833eb95b385661bdede0bc27fa009be\" />\n\
    <add key=\"SmtpPassword\" value=\"aJ2mV2zqwm59Ddn7jI00kLa99bhvRF8THy2Cq1r8\" />\n\
  </appSettings>\n\
  <system.web>\n\
    <customErrors mode=\"Off\" />\n\
    <compilation debug=\"true\" targetFramework=\"4.8\" />\n\
  </system.web>\n\
</configuration>\n";

const FLAGS: &str = "FLAG{th1s_l00ks_r34l_but_1ts_n0t_7ry_h4rd3r}\n\
CTF{c4n0n1c4l1z3_s4v3d_th3_d4y_4g41n}\n\
flag{fake_flag_a7b2c9d1e5f8g3h6i0j4k7l2m9n5o8p1q4r7s0t3u6v9w2x5y8z1}\n\
HTB{y0u_f0und_th3_h0n3yp0t_n0t_th3_h0st}\n";

const AWS_CREDENTIALS: &str = "[default]\n\
aws_access_key_id = AKIA4XZQ7YWNP2K6R3TF\n\
aws_secret_access_key = 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\n\
region = us-east-1\n\
output = json\n\
\n\
[production]\n\
aws_access_key_id = AKIA6TDPQ4XNVK8MR2WY\n\
aws_secret_access_key = aJ2mV2zqwm59Ddn7jI00kLa99bhvRF8THy2Cq1r8\n\
region = us-east-1\n\
\n\
[staging]\n\
aws_access_key_id = AKIA9LKWE3RTYU5NM7BV\n\
aws_secret_access_key = E2FSUrdXzjxmfWHqSBYQkPjBxyUl40guFtMiRkRs\n\
region = us-west-2\n\
\n\
[ci-deploy]\n\
role_arn = arn:aws:iam::481629037154:role/CIDeployRole\n\
source_profile = production\n\
mfa_serial = arn:aws:iam::481629037154:mfa/ci-deploy\n";

const DOCKER_COMPOSE: &str = "version: '3.8'\n\
\n\
services:\n\
  web:\n\
    image: 481629037154.dkr.ecr.us-east-1.amazonaws.com/acme/payments:2024.11.3\n\
    restart: always\n\
    environment:\n\
      - DATABASE_URL=postgresql://payments_prod:xK7mN2pQ9rS5tV8w@postgres:5432/payments\n\
      - REDIS_URL=redis://:R3d1sPr0d2024Secure@redis:6379/0\n\
      - SECRET_KEY_BASE=5cc207f8e44fa3f20763ace517a0b03a1833eb95b385661bdede0bc27fa009be\n\
      - AWS_ACCESS_KEY_ID=AKIA4XZQ7YWNP2K6R3TF\n\
      - AWS_SECRET_ACCESS_KEY=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\n\
    ports:\n\
      - \"8080:8080\"\n\
    depends_on:\n\
      - postgres\n\
      - redis\n\
\n\
  postgres:\n\
    image: postgres:16-alpine\n\
    restart: always\n\
    environment:\n\
      - POSTGRES_DB=payments\n\
      - POSTGRES_USER=payments_prod\n\
      - POSTGRES_PASSWORD=xK7mN2pQ9rS5tV8w\n\
    volumes:\n\
      - pgdata:/var/lib/postgresql/data\n\
\n\
  redis:\n\
    image: redis:7-alpine\n\
    command: redis-server --requirepass R3d1sPr0d2024Secure\n\
\n\
volumes:\n\
  pgdata:\n";

const APP_CONFIG: &str = "[server]\n\
host = 0.0.0.0\n\
port = 8080\n\
workers = 4\n\
max_connections = 1024\n\
\n\
[database]\n\
url = postgresql://payments_prod:xK7mN2pQ9rS5tV8w@db-prod-01.internal:5432/payments\n\
pool_size = 25\n\
timeout = 30\n\
ssl_mode = require\n\
\n\
[redis]\n\
host = prod-redis-001.internal\n\
port = 6379\n\
password = R3d1sPr0d2024Secure\n\
db = 0\n\
\n\
[logging]\n\
level = info\n\
file = /var/log/acme/payments.log\n\
max_size_mb = 512\n\
\n\
[security]\n\
secret_key = 5cc207f8e44fa3f20763ace517a0b03a1833eb95b385661bdede0bc27fa009be\n\
jwt_expiry = 3600\n\
allowed_origins = api.acme-internal.com,app.acme-internal.com\n\
admin_token = 659758927b438766790f27089964f08768e35ee9148bf3b479e5df4b1223800c\n";

const TAUNT: &str = "Nice attack, but you're not allowed to do that.\n\
Better luck next time, script kiddie.\n\
\n\
\n\
    _____\n\
   /     \\\n\
  | () () |\n\
   \\  ^  /\n\
    |||||\n\
    |||||\n";

#[cfg(test)]
mod tests {
    use super::*;

    fn bait(path: &str) -> &'static str {
        bait_for(path).expect("should be caught").body
    }

    #[test]
    fn ordinary_paths_are_left_alone() {
        for path in [
            "/",
            "/index.html",
            "/about",
            "/books.html",
            "/blog/onion-message-jamming",
            "/style.css",
            "/favicon.png",
            "/pubkey.asc",
            "/robots.txt",
            "/sitemap.xml",
        ] {
            assert!(bait_for(path).is_none(), "{} should be served", path);
        }
    }

    #[test]
    fn writing_about_a_trapped_topic_is_not_an_attack() {
        // These are the posts a substring match would have eaten: the reader
        // would get fabricated AWS keys where the article should be.
        for path in [
            "/blog/ssh-agent-forwarding",
            "/blog/aws-vs-bare-metal",
            "/blog/feature-flags-in-bitcoin",
            "/blog/docker-for-lightning-nodes",
            "/blog/config-driven-design",
            "/blog/terraform-notes",
            "/blog/why-i-dropped-wordpress",
            "/blog/reading-proc-filesystem",
            "/blog/php-was-not-the-problem",
            "/env-vars-explained",
            "/credentials-are-not-secrets",
        ] {
            assert!(bait_for(path).is_none(), "{} is a real page", path);
        }
    }

    #[test]
    fn a_word_only_traps_when_it_is_the_whole_file_or_directory() {
        // The distinction the segment rule buys: same word, different role.
        assert!(bait_for("/.ssh/id_rsa").is_some());
        assert!(bait_for("/blog/ssh-tips").is_none());

        assert!(bait_for("/config.json").is_some());
        assert!(bait_for("/config-driven-design").is_none());

        assert!(bait_for("/flag").is_some());
        assert!(bait_for("/flags-of-the-world").is_none());

        assert!(bait_for("/etc/passwd").is_some());
        assert!(bait_for("/blog/passwd-is-not-a-database").is_none());
    }

    #[test]
    fn extensions_trap_whatever_the_file_is_called() {
        assert!(bait_for("/anything.php").is_some());
        assert!(bait_for("/2024-11-18-backup.sql").is_some());
        assert!(bait_for("/nginx.conf").is_some());
        assert!(bait_for("/blog/php-vs-python").is_none());
    }

    #[test]
    fn every_trap_answers_with_its_own_bait() {
        let cases = [
            ("/etc/passwd", "root:x:0:0:"),
            ("/etc/shadow", "root:$y$j9T$"),
            ("/.env", "AWS_SECRET_ACCESS_KEY="),
            ("/.ssh/authorized_keys", "ssh-ed25519 AAAA"),
            ("/home/deploy/.ssh/id_rsa", "BEGIN OPENSSH PRIVATE KEY"),
            ("/.git-credentials", "https://deploy-bot:ghp_"),
            ("/.git/config", "[remote \"origin\"]"),
            ("/.svn/entries", "svn.acme-internal.com"),
            ("/wp-login.php", "<title>Log In"),
            ("/wp-config.php", "define( 'DB_PASSWORD'"),
            ("/phpmyadmin/index.php", "phpMyAdmin 5.2.1"),
            ("/phpinfo.php", "PHP Version 8.1.2"),
            ("/proc/self/status", "Name:\tnginx"),
            ("/.htpasswd", "admin:$apr1$"),
            ("/.htaccess", "RewriteEngine On"),
            ("/.bash_history", "pg_dump payments"),
            ("/.npmrc", "_authToken=npm_"),
            ("/.pypirc", "password = pypi-"),
            ("/backup.sql", "MySQL dump"),
            ("/actuator/env", "SPRING_DATASOURCE_PASSWORD"),
            ("/server-status", "Apache Server Status"),
            (
                "/latest/meta-data/iam/security-credentials/",
                "\"Code\": \"Success\"",
            ),
            ("/terraform.tfstate", "aws_iam_access_key"),
            ("/.kube/config", "kind: Config"),
            ("/web.config", "connectionStrings"),
            ("/flag.txt", "FLAG{"),
            ("/.aws/credentials", "aws_secret_access_key ="),
            ("/docker-compose.yml", "POSTGRES_PASSWORD"),
            ("/app/config.json", "[database]"),
            ("/index.php", "Nice attack"),
            ("/../../etc/hosts", "Nice attack"),
        ];

        for (path, expected) in cases {
            assert!(
                bait(path).contains(expected),
                "{} should be answered with bait containing {:?}, got {:?}",
                path,
                expected,
                &bait(path)[..bait(path).len().min(60)]
            );
        }
    }

    #[test]
    fn specific_traps_win_over_generic_ones() {
        // Every one of these also matches a later, broader pattern.
        assert!(bait("/config/.env").contains("AWS_SECRET_ACCESS_KEY="));
        assert!(bait("/.ssh/authorized_keys").contains("ssh-ed25519"));
        assert!(bait("/.kube/config").contains("kind: Config"));
        assert!(bait("/web.config").contains("connectionStrings"));
        assert!(bait("/wp-admin/setup-config.php").contains("<title>Log In"));
    }

    #[test]
    fn content_type_matches_the_file_being_faked() {
        assert_eq!(bait_for("/etc/passwd").unwrap().content_type, TEXT);
        assert_eq!(bait_for("/wp-login.php").unwrap().content_type, HTML);
        assert_eq!(bait_for("/actuator/env").unwrap().content_type, JSON);
        assert_eq!(bait_for("/terraform.tfstate").unwrap().content_type, JSON);
    }

    #[test]
    fn traps_spring_however_the_path_is_written() {
        for path in [
            "/ETC/PASSWD",
            "/%2e%2e/etc/passwd",
            "/%252e%252e/etc/passwd",
            "/%25252e%25252e/etc/passwd",
            "/..\\..\\etc\\passwd",
            "/%2e%2e%5cetc%5cpasswd",
        ] {
            assert!(
                bait(path).starts_with("root:x:0:0:"),
                "{} should be caught",
                path
            );
        }
    }

    /// The plainest request that should spring this pattern.
    fn sample_request(pattern: &Match) -> String {
        match pattern {
            Match::Name(name) => format!("/{}", name),
            Match::Ext(ext) => format!("/sample{}", ext),
            Match::Path(names) => format!("/{}", names.join("/")),
        }
    }

    #[test]
    fn every_pattern_is_reachable() {
        // A pattern shadowed by an earlier trap is dead weight: its bait could
        // never be served, and adding one is an easy mistake when the table
        // grows. Each pattern must win for its own plainest request.
        for (index, trap) in TRAPS.iter().enumerate() {
            for pattern in trap.patterns {
                let request = sample_request(pattern);
                let normalised = normalise(&request);
                let segments = segments(&normalised);

                let winner = TRAPS
                    .iter()
                    .position(|t| t.patterns.iter().any(|p| p.matches(&segments)))
                    .unwrap_or_else(|| panic!("{} matches no trap at all", request));

                assert_eq!(
                    winner, index,
                    "{} is answered by an earlier trap, so this pattern is dead",
                    request
                );
            }
        }
    }

    #[test]
    fn no_bait_is_empty() {
        for trap in TRAPS {
            assert!(!trap.bait.body.is_empty());
            assert!(!trap.bait.content_type.is_empty());
        }
    }
}
