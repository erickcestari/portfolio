//! The honeypot: paths only an attacker asks for, and the bait they get back.
//!
//! One table drives both halves of the trap, so a pattern can never be
//! recognised without having an answer, or answer without being recognised.
//! First match wins, which is why specific traps are listed before generic
//! ones: `/config/.env` is an env-file hunt, not a config-file hunt.
//!
//! The bait is fabricated. Every credential here is random but in its real
//! format, valid nowhere, so a scanner that harvests it spends its time on
//! dead ends instead of on the real internet. The files tell one story about
//! one company, so a secret reappears wherever a real leak would repeat it.
//! Its domains resolve nowhere and `.internal` never will, so following the
//! bait cannot land a scanner on someone else's servers.

/// What a caught request is answered with.
#[derive(Clone, Copy)]
pub struct Bait {
    /// What the scanner was after, as shown on the public `/honeypot` page.
    /// Fixed per trap, so nothing a scanner typed is ever published.
    pub label: &'static str,
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
    trap(
        "/etc/passwd",
        &[Match::Path(&["etc", "passwd"])],
        TEXT,
        PASSWD,
    ),
    trap(
        "/etc/shadow",
        &[Match::Path(&["etc", "shadow"])],
        TEXT,
        SHADOW,
    ),
    trap(".env files", &[Match::Name(".env")], TEXT, DOTENV),
    trap(
        "authorized_keys",
        &[Match::Name("authorized_keys")],
        TEXT,
        AUTHORIZED_KEYS,
    ),
    trap(
        "SSH private keys",
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
        "git credentials",
        &[Match::Name(".git-credentials"), Match::Name(".netrc")],
        TEXT,
        GIT_CREDENTIALS,
    ),
    trap(
        ".git directories",
        &[Match::Name(".git"), Match::Name(".gitconfig")],
        TEXT,
        GIT_CONFIG,
    ),
    trap(
        ".svn directories",
        &[Match::Name(".svn")],
        TEXT,
        SVN_ENTRIES,
    ),
    trap(
        "WordPress logins",
        &[Match::Name("wp-login"), Match::Name("wp-admin")],
        HTML,
        WP_LOGIN,
    ),
    trap(
        "wp-config.php",
        &[Match::Name("wp-config"), Match::Name("wordpress")],
        TEXT,
        WP_CONFIG,
    ),
    trap(
        "phpMyAdmin",
        &[Match::Name("phpmyadmin"), Match::Name("pma")],
        HTML,
        PHPMYADMIN,
    ),
    trap(
        "phpinfo()",
        &[Match::Name("phpinfo"), Match::Name("info.php")],
        HTML,
        PHPINFO,
    ),
    trap("/proc", &[Match::Name("proc")], TEXT, PROC_STATUS),
    trap(".htpasswd", &[Match::Name(".htpasswd")], TEXT, HTPASSWD),
    trap(".htaccess", &[Match::Name(".htaccess")], TEXT, HTACCESS),
    trap(
        "shell history",
        &[Match::Name(".bash_history"), Match::Name(".zsh_history")],
        TEXT,
        BASH_HISTORY,
    ),
    trap("npm tokens", &[Match::Name(".npmrc")], TEXT, NPMRC),
    trap("PyPI tokens", &[Match::Name(".pypirc")], TEXT, PYPIRC),
    trap(
        "SQL dumps",
        &[Match::Ext(".sql"), Match::Name("mysqldump")],
        TEXT,
        SQL_DUMP,
    ),
    trap(
        "Spring actuator",
        &[Match::Name("actuator")],
        JSON,
        ACTUATOR_ENV,
    ),
    trap(
        "Apache server-status",
        &[Match::Name("server-status"), Match::Name("server-info")],
        HTML,
        SERVER_STATUS,
    ),
    trap(
        "cloud metadata",
        &[
            Match::Name("meta-data"),
            Match::Name("user-data"),
            Match::Name("169.254.169.254"),
        ],
        JSON,
        IMDS_CREDENTIALS,
    ),
    trap(
        "Terraform state",
        &[Match::Ext(".tfstate"), Match::Name("terraform")],
        JSON,
        TFSTATE,
    ),
    trap(
        "kubeconfig",
        &[
            Match::Name("kubeconfig"),
            Match::Name(".kube"),
            Match::Path(&["kube", "config"]),
        ],
        TEXT,
        KUBECONFIG,
    ),
    trap("web.config", &[Match::Name("web.config")], TEXT, WEB_CONFIG),
    trap(
        "CTF flags",
        &[Match::Name("flag"), Match::Name("ctf")],
        TEXT,
        FLAGS,
    ),
    trap(
        "AWS credentials",
        &[
            Match::Name(".aws"),
            Match::Name("aws"),
            Match::Name("credentials"),
        ],
        TEXT,
        AWS_CREDENTIALS,
    ),
    trap(
        "Docker configs",
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
        "config files",
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
    trap(
        "traversal and PHP probes",
        &[Match::Name(".."), Match::Ext(".php")],
        TEXT,
        TAUNT,
    ),
];

const fn trap(
    label: &'static str,
    patterns: &'static [Match],
    content_type: &'static str,
    body: &'static str,
) -> Trap {
    Trap {
        patterns,
        bait: Bait {
            label,
            body,
            content_type,
        },
    }
}

// Raw strings on purpose: a `\` line continuation strips the next line's
// leading whitespace, which flattens the YAML and SQL bait into nonsense.

const PASSWD: &str = r#"root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:105::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:106:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
syslog:x:105:111::/nonexistent:/usr/sbin/nologin
uuidd:x:106:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:107:113::/nonexistent:/usr/sbin/nologin
sshd:x:108:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
landscape:x:110:114::/var/lib/landscape:/usr/sbin/nologin
postgres:x:111:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
redis:x:112:118::/var/lib/redis:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
deploy:x:1001:1001:Deploy User,,,:/home/deploy:/bin/bash
"#;

const SHADOW: &str = r#"root:$y$j9T$PoYbxRToVsr5KDZRq0/y5D$3oWsqygXgipse64AePMeZSqB/e5rxzhrsj2zyMNRGHj:19847:0:99999:7:::
daemon:*:19835:0:99999:7:::
bin:*:19835:0:99999:7:::
sys:*:19835:0:99999:7:::
sync:*:19835:0:99999:7:::
games:*:19835:0:99999:7:::
man:*:19835:0:99999:7:::
www-data:*:19835:0:99999:7:::
backup:*:19835:0:99999:7:::
nobody:*:19835:0:99999:7:::
systemd-network:!*:19835::::::
systemd-resolve:!*:19835::::::
messagebus:!:19835::::::
syslog:!:19835::::::
sshd:!:19841::::::
postgres:$y$j9T$DWPjogR0UIbYAkYwuFrr9X$jd/ys1gAH0r9Kw1gwIxrkVhG3ut.aZuSL6QAoSjDPwP:19844:0:99999:7:::
redis:!:19844::::::
ubuntu:$y$j9T$6xzgubtdhLayyU5AHmP1Cw$rWwOpK6J.5pH5erlemU/CoekfONNImZb4m53yHLtG3k:19851:0:99999:7:::
deploy:$y$j9T$dhci1jZjCAI2XV5Nqd9Shr$TdytPLXKaUbZUZyJX4RTTBpWoPCwiGwcclva1IWUL93:19849:0:99999:7:::
"#;

const DOTENV: &str = r#"APP_NAME=brindle-payments
APP_ENV=production
APP_DEBUG=false
APP_URL=https://api.brindlepay.com

# Database
DATABASE_URL=postgresql://payments_prod:gDQSnmQTAqjmMEyG9qLZJtU6@db-prod-01.9nlp73y6cgfg.us-east-1.rds.amazonaws.com:5432/payments
DB_POOL_SIZE=25
DB_SSL_MODE=require

# Cache and queue
REDIS_URL=redis://:rwZHvZ9IbOzEFnPiJOoYVeahWUhcTmac@prod-redis-001.xd2r94.ng.0001.use1.cache.amazonaws.com:6379/0
QUEUE_CONNECTION=redis

# Application secrets
SECRET_KEY_BASE=f6cb710cdef900df44aafcb174d114cff1aea6c668f2a7aea1910f0e0b71fe2a6fab3d0b000727d9dc4fc6e5e0801dbdd8ec2fd85c1f213248503d465e08caea
JWT_SECRET=77c8dea7067d075f14f6fc2e8400417b1e984dbd6faaa01f8f82776ba68475a4
SESSION_LIFETIME=120

# AWS
AWS_ACCESS_KEY_ID=AKIAXAI2T4JRCPSBHZNB
AWS_SECRET_ACCESS_KEY=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
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=brindlepay-prod-assets

# Stripe
STRIPE_KEY=pk_live_51hwprgQBPEDypD1n31HB7VXhxcrE2vCc229RsvTZRd2JZ8Rsabzcps5Eo8AInE3eNZ2C9JYRi0xRv6jZZltpkaSNzhCVgjBZxq
STRIPE_SECRET=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
STRIPE_WEBHOOK_SECRET=whsec_TA8f9ti9VPhrtz9m48FrpAKhlwGi7Uft

# Mail
MAIL_MAILER=smtp
MAIL_HOST=email-smtp.us-east-1.amazonaws.com
MAIL_PORT=587
MAIL_USERNAME=AKIAXAI2T4JRFRV5Z6UF
MAIL_PASSWORD=BMFlG/4kmAMUaeG71GOJW9w2XHEUwINN7gsUeT8xEC96
MAIL_FROM_ADDRESS=no-reply@brindlepay.com
SENDGRID_API_KEY=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

# Third party
GITHUB_TOKEN=ghp_wHIB91ljqGu166xwl7eo8KJkUhg8RKShlkOD
SLACK_BOT_TOKEN=xoxb-1754065475365-2140858365466-vgpsDjXAicZPPhSlO0ZLsnBj
OPENAI_API_KEY=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
TWILIO_ACCOUNT_SID=ACfd56fc7c47b759e70ad1c79b86945eb5
TWILIO_AUTH_TOKEN=66f3b2fb87523f2ab5abfd41cf2c6fa8
SENTRY_DSN=https://554bca8c857bcbc0def9886860f2b5b8@o9996466.ingest.us.sentry.io/1984576039842334
"#;

const AUTHORIZED_KEYS: &str = r#"# Managed by Ansible, do not edit by hand
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPW1BwUeG+uyH6WV3KOjOuBk+3cBUVzAJrwtuKJpXPdK deploy@ci-runner-01
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICVZdRSQzK51iE7ppAPUHn3oIqJgvpRRQRyXg1X5hki5 ops@bastion-prod
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCoim2WsuZ19haaM3p6gy1i58m3LBJmnWkLOYq/RPRhqioH+NkWpYpzMwB2lJ1KwZG7KALVPW+p4vQUtacykWfMCIgxsu3cR3bfLix4e59ZSP4lObgq8pMcgB290B4QN/63UZvsvZik4/wb1N0LnXS1rX9i7xcMqMIdYdKYb54+/kTZgi9Tr1Cv9eiUHuMx30LmuRNsZKDTQKcH5vHBk3I+FFId1vIdJ2I/okG/5Jk3QcZBtwAKkCGiVqGeLeFSkofK1BMJvqCTkRj8UW5K7QCVPVQLpsJ1oKtT73WMqahu2e8ZKGOxOEuJ1tS9HZQZQzzWzw8Drw/afXfCcUwyvkQl3VewlLMmaItkHuyAc0bQty7BEUDzrEOqYqE2hi3rZ0bWsincW32D4cNzyYMreBEAJIJqYRuPrHEYnC6/0sVnJKQ4qMkw9bus/4KOvIBzogaauU5tnVtUwIgdc39GCFXCOZZJlJRBmApVh5lpy04BLoAjL7cCBEc6ea0SPFwKuMc= ubuntu@jump-host
"#;

const SSH_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
"#;

const GIT_CREDENTIALS: &str = r#"https://deploy-bot:ghp_wHIB91ljqGu166xwl7eo8KJkUhg8RKShlkOD@github.com
https://brindle-ci:glpat-F7dSEdMH9JdysrX-YuAn@gitlab.brindle.internal
"#;

const GIT_CONFIG: &str = r#"[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://deploy-bot:ghp_wHIB91ljqGu166xwl7eo8KJkUhg8RKShlkOD@github.com/brindlepay/payments-api.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
[branch "release/2026.10"]
	remote = origin
	merge = refs/heads/release/2026.10
[user]
	name = CI Deploy
	email = deploy@brindlepay.com
"#;

const SVN_ENTRIES: &str = r#"10

dir
48213
https://svn.brindle.internal/repos/payments/trunk
https://svn.brindle.internal/repos/payments


2024-09-14T08:21:47.184290Z
48211
mkowalski
svn:special svn:externals svn:needs-lock
"#;

const WP_LOGIN: &str = r#"<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Log In &lsaquo; Brindle &#8212; WordPress</title>
<meta name='robots' content='max-image-preview:large, noindex, noarchive' />
<link rel='stylesheet' id='login-css' href='https://brindlepay.com/wp-admin/css/login.min.css?ver=6.4.2' media='all' />
<meta name='referrer' content='strict-origin-when-cross-origin' />
<meta name="viewport" content="width=device-width" />
</head>
<body class="login no-js login-action-login wp-core-ui  locale-en-us">
<div id="login">
	<h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
	<form name="loginform" id="loginform" action="https://brindlepay.com/wp-login.php" method="post">
		<p>
			<label for="user_login">Username or Email Address</label>
			<input type="text" name="log" id="user_login" class="input" value="" size="20" autocapitalize="off" autocomplete="username" required="required" />
		</p>
		<div class="user-pass-wrap">
			<label for="user_pass">Password</label>
			<div class="wp-pwd">
				<input type="password" name="pwd" id="user_pass" class="input password-input" value="" size="20" autocomplete="current-password" spellcheck="false" required="required" />
			</div>
		</div>
		<p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever"  /> <label for="rememberme">Remember Me</label></p>
		<p class="submit">
			<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
			<input type="hidden" name="redirect_to" value="https://brindlepay.com/wp-admin/" />
			<input type="hidden" name="testcookie" value="1" />
		</p>
	</form>
	<p id="nav">
		<a href="https://brindlepay.com/wp-login.php?action=lostpassword">Lost your password?</a>
	</p>
	<p id="backtoblog"><a href="https://brindlepay.com/">&larr; Go to Brindle</a></p>
</div>
</body>
</html>
"#;

const WP_CONFIG: &str = r#"<?php
/**
 * The base configuration for WordPress
 *
 * @package WordPress
 */

// ** Database settings ** //
define( 'DB_NAME', 'brindle_wp' );
define( 'DB_USER', 'wp_admin' );
define( 'DB_PASSWORD', 'Br1ndl3-wp!4PY4Sf' );
define( 'DB_HOST', 'mysql-prod-01.9nlp73y6cgfg.us-east-1.rds.amazonaws.com' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 */
define( 'AUTH_KEY',         'wp*5Q)S0F~Vx,8,UK_{qXN5lkLQ1Uw28/^0ukq}mn!6x:.aW6Uc$c[qnV9a0jHZR' );
define( 'SECURE_AUTH_KEY',  'c>Xed(vxO{Q`WqfS,*{FcFSWn9M|2N_|RKA~sw}(a_>+`Xc&;L4XSb}6|+(,qYHs' );
define( 'LOGGED_IN_KEY',    'u2)DHay`(Gs#+SNT%+:8SI4GAycxWYpsRsPo%0SPvF+$l;:shQp|vV(M<}4/b%=R' );
define( 'NONCE_KEY',        '!C<^0M7vFrSB<7@f}]t+]1yy2>58k4>W!O1zw5rD(s%6w#6ZA=fOq07.L1A_+#XW' );
define( 'AUTH_SALT',        '|Wr`PuWb{GUxwHMVJ3nZf7Y)0DLmP}zd9sAYZ(Yb(4lh}d.jg)@q2L_*$+]n.HO2' );
define( 'SECURE_AUTH_SALT', 'O?~ZCPCXi8S8vMjU55LDS6TS|k!FVnZ9~aQs.|Ha#&9;p{TFM^)TR$PU_GH h5n=' );
define( 'LOGGED_IN_SALT',   '?bqQ(V[h]m-b1K31EyT{-WutqbEA~u|)zSc|#LQwFbcNwsUR:}C]cOq$1Mi2xZea' );
define( 'NONCE_SALT',       '=Pq|UBI9sDKH:I<!&tV#4wc1+G*$1eUv!q<WBGZhU`<dQJi}ESU-W 4;k`db,WM:' );
/**#@-*/

$table_prefix = 'wp_';

define( 'WP_DEBUG', false );
define( 'DISALLOW_FILE_EDIT', true );
define( 'WP_MEMORY_LIMIT', '256M' );

/* That's all, stop editing! Happy publishing. */

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

require_once ABSPATH . 'wp-settings.php';
"#;

const PHPMYADMIN: &str = r#"<!DOCTYPE HTML>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8" />
<title>phpMyAdmin</title>
<link rel="stylesheet" type="text/css" href="/phpmyadmin/themes/pmahomme/css/theme.css" />
</head>
<body class="loginform">
<div class="container">
<a href="https://www.phpmyadmin.net/" class="logo">phpMyAdmin 5.2.1</a>
<form method="post" action="/phpmyadmin/index.php?route=/" name="login_form" class="login">
	<label for="input_username">Username:</label>
	<input type="text" name="pma_username" id="input_username" value="" />
	<label for="input_password">Password:</label>
	<input type="password" name="pma_password" id="input_password" value="" />
	<input type="hidden" name="server" value="1" />
	<input type="submit" name="input_go" id="input_go" value="Go" />
</form>
</div>
</body>
</html>
"#;

const PHPINFO: &str = r#"<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"><head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>PHP 8.1.2-1ubuntu2.14 - phpinfo()</title><meta name="ROBOTS" content="NOINDEX,NOFOLLOW,NOARCHIVE" /></head>
<body><div class="center">
<table>
<tr class="h"><td><h1 class="p">PHP Version 8.1.2-1ubuntu2.14</h1></td></tr>
</table>
<table>
<tr><td class="e">System </td><td class="v">Linux web-prod-01 5.15.0-89-generic #99-Ubuntu SMP Mon Oct 30 20:42:41 UTC 2023 x86_64 </td></tr>
<tr><td class="e">Server API </td><td class="v">FPM/FastCGI </td></tr>
<tr><td class="e">Loaded Configuration File </td><td class="v">/etc/php/8.1/fpm/php.ini </td></tr>
</table>
<h2>Core</h2>
<table>
<tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">allow_url_include</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">disable_functions</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">open_basedir</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
</table>
<h2>PHP Variables</h2>
<table>
<tr class="h"><th>Variable</th><th>Value</th></tr>
<tr><td class="e">$_SERVER['USER']</td><td class="v">www-data</td></tr>
<tr><td class="e">$_SERVER['DOCUMENT_ROOT']</td><td class="v">/var/www/brindle/public</td></tr>
<tr><td class="e">$_SERVER['SERVER_NAME']</td><td class="v">brindlepay.com</td></tr>
<tr><td class="e">$_SERVER['DB_HOST']</td><td class="v">mysql-prod-01.9nlp73y6cgfg.us-east-1.rds.amazonaws.com</td></tr>
<tr><td class="e">$_SERVER['DB_PASSWORD']</td><td class="v">Br1ndl3-wp!4PY4Sf</td></tr>
</table>
</div></body></html>
"#;

const PROC_STATUS: &str = r#"Name:	php-fpm8.1
Umask:	0022
State:	R (running)
Tgid:	2317
Ngid:	0
Pid:	2317
PPid:	1094
TracerPid:	0
Uid:	33	33	33	33
Gid:	33	33	33	33
FDSize:	64
Groups:	33
NStgid:	2317
NSpid:	2317
NSpgid:	1094
NSsid:	1094
VmPeak:	  286412 kB
VmSize:	  284988 kB
VmLck:	       0 kB
VmPin:	       0 kB
VmHWM:	   47920 kB
VmRSS:	   46872 kB
RssAnon:	   21604 kB
RssFile:	   19140 kB
RssShmem:	    6128 kB
VmData:	   24316 kB
VmStk:	     132 kB
VmExe:	    3248 kB
VmLib:	   41960 kB
VmPTE:	     308 kB
VmSwap:	       0 kB
Threads:	1
SigQ:	0/31196
SigPnd:	0000000000000000
ShdPnd:	0000000000000000
SigBlk:	0000000000000000
SigIgn:	0000000000001000
SigCgt:	0000000184004a07
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff
Seccomp:	0
Cpus_allowed_list:	0-3
Mems_allowed_list:	0
voluntary_ctxt_switches:	6481
nonvoluntary_ctxt_switches:	217
"#;

const HTPASSWD: &str = r#"admin:$apr1$et.OWmcJ$j2xRvwSBih7YouYntXvcs.
deploy:$apr1$c4Q0k0s/$19wQdOvbtGZpXXqVPTS/V.
monitoring:$2y$10$7YH57PnknZXHgPlSg9OG0.16w4nVmZkItXHwYpc/zLOa1MkMvIrhS
backup:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=
"#;

const HTACCESS: &str = r#"RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]

<Files "config.inc.php">
	Require all denied
</Files>

AuthType Basic
AuthName "Staging Area"
AuthUserFile /var/www/brindle/.htpasswd
Require valid-user

php_value upload_max_filesize 64M
php_value post_max_size 64M
"#;

const BASH_HISTORY: &str = r#"cd /var/www/brindle
git pull origin main
sudo systemctl restart apache2
psql -h db-prod-01.9nlp73y6cgfg.us-east-1.rds.amazonaws.com -U payments_prod -d payments
export PGPASSWORD='gDQSnmQTAqjmMEyG9qLZJtU6'
pg_dump payments > /tmp/payments-2026-10-05.sql
aws s3 cp /tmp/payments-2026-10-05.sql s3://brindlepay-prod-assets/backups/
mysql -u wp_admin -p'Br1ndl3-wp!4PY4Sf' brindle_wp
ssh -i ~/.ssh/id_rsa deploy@10.0.3.14
docker compose -f /srv/brindle/docker-compose.yml up -d
curl -H "Authorization: Bearer ghp_wHIB91ljqGu166xwl7eo8KJkUhg8RKShlkOD" https://api.github.com/user
history -c
"#;

const NPMRC: &str = r#"//registry.npmjs.org/:_authToken=npm_KNT2avrdAmdHREUJRNrgQUC8uGlTqI21g8Gu
//npm.pkg.github.com/:_authToken=ghp_ZumXDmwJqQk33nmdkfuFx39tmWlT2YfjGQm1
@brindlepay:registry=https://npm.pkg.github.com
always-auth=true
engine-strict=true
"#;

const PYPIRC: &str = r#"[distutils]
index-servers =
    pypi
    brindle

[pypi]
username = __token__
password = pypi-AgEIcHlwaS5vcmcCJDM3NmQ1NjJiLWY3MjktNDg3YS1iNTBjLWY1YWVhOTIyNjBkYwACInsidmVyc2lvbiI6MSwicGVybWlzc2lvbnMiOiJ1c2VyIn0AAAYgiKfecOEG7yzGy99wSxJQZpORbx-qwiOHsET1ku0E3sE

[brindle]
repository = https://pypi.brindle.internal/simple
username = ci-publisher
password = 2niAmuV8Mc3MbtbctKVNsa5YRaoOxbXm
"#;

const SQL_DUMP: &str = r#"-- MySQL dump 10.13  Distrib 8.0.35, for Linux (x86_64)
--
-- Host: mysql-prod-01    Database: brindle_wp
-- ------------------------------------------------------
-- Server version	8.0.35-0ubuntu0.22.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40103 SET TIME_ZONE='+00:00' */;

--
-- Table structure for table `wp_users`
--

DROP TABLE IF EXISTS `wp_users`;
CREATE TABLE `wp_users` (
  `ID` bigint unsigned NOT NULL AUTO_INCREMENT,
  `user_login` varchar(60) COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT '',
  `user_pass` varchar(255) COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT '',
  `user_nicename` varchar(50) COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT '',
  `user_email` varchar(100) COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT '',
  `user_url` varchar(100) COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT '',
  `user_registered` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `user_activation_key` varchar(255) COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT '',
  `user_status` int NOT NULL DEFAULT '0',
  `display_name` varchar(250) COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`ID`),
  KEY `user_login_key` (`user_login`),
  KEY `user_nicename` (`user_nicename`),
  KEY `user_email` (`user_email`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

--
-- Dumping data for table `wp_users`
--

LOCK TABLES `wp_users` WRITE;
/*!40000 ALTER TABLE `wp_users` DISABLE KEYS */;
INSERT INTO `wp_users` VALUES (1,'brindle_admin','$P$Bws31fJ3CP9ajT5v4XAEGYasFaW7DhR6','brindle_admin','admin@brindlepay.com','https://brindlepay.com','2021-03-04 09:12:44','',0,'brindle_admin'),(2,'ops','$P$BCfhDoOAY.kylRkCKwRpzaVh6S8pRc2L','ops','ops@brindlepay.com','','2021-06-18 14:03:21','',0,'Ops'),(5,'mkowalski','$P$B7bf9X7k1T5iPr1yx.68w6BV3OQt6lti','mkowalski','m.kowalski@brindlepay.com','','2022-01-27 11:47:09','',0,'Marta Kowalski'),(8,'ldiaz','$P$BSrDKDU.OYzTv0ZK8fNQ/V43cXPGpwRz','ldiaz','l.diaz@brindlepay.com','','2023-08-02 16:20:51','',0,'Lucas Diaz');
/*!40000 ALTER TABLE `wp_users` ENABLE KEYS */;
UNLOCK TABLES;

-- Dump completed on 2026-10-05  3:15:22
"#;

const ACTUATOR_ENV: &str = r#"{
  "activeProfiles": ["production"],
  "propertySources": [
    {
      "name": "systemEnvironment",
      "properties": {
        "SPRING_DATASOURCE_URL": {"value": "jdbc:postgresql://db-prod-01.9nlp73y6cgfg.us-east-1.rds.amazonaws.com:5432/payments"},
        "SPRING_DATASOURCE_USERNAME": {"value": "payments_prod"},
        "SPRING_DATASOURCE_PASSWORD": {"value": "gDQSnmQTAqjmMEyG9qLZJtU6"},
        "AWS_ACCESS_KEY_ID": {"value": "AKIAXAI2T4JRCPSBHZNB"},
        "AWS_SECRET_ACCESS_KEY": {"value": "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"},
        "JWT_SIGNING_KEY": {"value": "77c8dea7067d075f14f6fc2e8400417b1e984dbd6faaa01f8f82776ba68475a4"}
      }
    },
    {
      "name": "applicationConfig: [classpath:/application-production.yml]",
      "properties": {
        "management.endpoints.web.exposure.include": {"value": "*"},
        "server.port": {"value": 8080}
      }
    }
  ]
}
"#;

const SERVER_STATUS: &str = r#"<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html><head>
<title>Apache Status</title>
</head><body>
<h1>Apache Server Status for brindlepay.com (via 127.0.0.1)</h1>

<dl><dt>Server Version: Apache/2.4.52 (Ubuntu) OpenSSL/3.0.2</dt>
<dt>Server MPM: event</dt>
<dt>Server Built: 2024-10-08T12:41:19
</dt></dl><hr /><dl>
<dt>Current Time: Monday, 12-Oct-2026 03:22:41 UTC</dt>
<dt>Restart Time: Sunday, 04-Oct-2026 02:14:07 UTC</dt>
<dt>Parent Server Config. Generation: 9</dt>
<dt>Parent Server MPM Generation: 8</dt>
<dt>Server uptime:  8 days 1 hour 8 minutes 34 seconds</dt>
<dt>Server load: 0.41 0.37 0.33</dt>
<dt>Total accesses: 4128377 - Total Traffic: 92.4 GB - Total Duration: 1847213</dt>
<dt>12 requests currently being processed, 38 idle workers</dt>
</dl>
<table border="0"><tr><th>Srv</th><th>PID</th><th>Client</th><th>VHost</th><th>Request</th></tr>
<tr><td><b>0-0</b></td><td>2317</td><td>10.0.1.22</td><td nowrap>api.brindlepay.com:443</td><td nowrap>POST /v1/payments/charge HTTP/1.1</td></tr>
<tr><td><b>0-1</b></td><td>2318</td><td>10.0.2.9</td><td nowrap>admin.brindlepay.com:443</td><td nowrap>GET /admin/users?token=d71a5c3268cb969bdbbd71a62125b052d0a6ebb9 HTTP/1.1</td></tr>
<tr><td><b>0-2</b></td><td>2319</td><td>10.0.1.22</td><td nowrap>api.brindlepay.com:443</td><td nowrap>GET /internal/health HTTP/1.1</td></tr>
</table>
</body></html>
"#;

const IMDS_CREDENTIALS: &str = r#"{
  "Code" : "Success",
  "LastUpdated" : "2026-10-12T02:58:14Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIAXAI2T4JRB5NYXVXF",
  "SecretAccessKey" : "1LEFFTwBLBn19Zq6auzFlqMX0vyL55RiVmlFVufA",
  "Token" : "IQoJb3JpZ2luX2Vj5BzME/CI6SZWwsqHTbUaTQz7n1p6Ox6E5YrM9H5jrJ8HPptOA0GJeLJx9q5W3jbT1vQuJUg6+TVBIMsqnO42/1jSvTjKn+5rHaFcubDhrLOpGXxiLgI9WnRD64W1IH4DegcbTpZfcFZK+1C5DcvHSaKCjW7e23xLeoBQBx9+5kISWX50uprW9xMO0D9R32MIhIaltZ19q76vSTCF+ooXl0P4UFgj2eayMWsC6t7unZPMloLHVRBiKW6QhzYQNWSeujL+jyEym7UECHy+sLdqaiTC5Trsjcq8ZDazqhDnix6LlyjkGjlRGgg73A1B7C20CllR34bWY9vcpZvXvR40lhTbn6X59A0Vq87r6s1w9WmVsp/jslI3X/XkMHh8MDTp0qlhf0C62Vm0xTOmNg+1CO/aZw/nI2lPAgaBJUeltZL7MIiw/qsr+j8uwglVn4/o2W2M2IAjygak7IFAKsfAmBC3f7FIUqBO7zGEm2Z0i+7xuMMCDvXHhY5JIWHnnHscg1XCVNCkI22A8FFcZBuYdscmW3+RtuHC+BfsQWYJuvJAwWqdumySq1GnZW8xrNWeHL57iT+IW6Uk1T6ViKTMnoDN+CQ/Y0vXLD77rSJbBqj7r6FdNDNADVVLjkpfbPVAk+08WYC9pGHVn4OJXTNu210Xo6KByvzjjzoEtmJ4qMxPDBLzQKxBGGvjZDEUC1yMptBHdpqHKh9wo9H7N9IVNPzdoxDYS0EBMyTvd7I/64rvqm7GGuatiRgzIkv2f0CvDvPY0zlWuyCtI8VrVG513AQv3cJVHzrD89Y2ISLV/L5I7d2/gmIDAbfOnzruC+pxtCMDdwuI+2VWHNCobE3yYrdwPdon2YupzI0DGSAHv8KZeK+N5DJk9ctxyqQoEAFZxyK34G/MN+qhJ9PUVv37MDgcQlStvfsA95cwLMkMpbl/Z02QRWYOWo8TBpvLAOPX+My/SCYDLhBamxOto7UxUvVisSqlXoRIZZ31C8mfFLU20mMRpNyLnavNaG3yD02d5zC7r+aP0oDns0SbHcZVIkUd==",
  "Expiration" : "2026-10-12T09:12:47Z"
}
"#;

const TFSTATE: &str = r#"{
  "version": 4,
  "terraform_version": "1.6.4",
  "serial": 187,
  "lineage": "8f2b41c7-6d93-4a15-b8e2-0c37fa951d64",
  "outputs": {
    "db_password": {"value": "gDQSnmQTAqjmMEyG9qLZJtU6", "type": "string", "sensitive": true},
    "rds_endpoint": {"value": "db-prod-01.9nlp73y6cgfg.us-east-1.rds.amazonaws.com:5432", "type": "string"}
  },
  "resources": [
    {
      "mode": "managed",
      "type": "aws_iam_access_key",
      "name": "ci_deploy",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "schema_version": 0,
          "attributes": {
            "id": "AKIAXAI2T4JRCPSBHZNB",
            "secret": "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",
            "status": "Active",
            "user": "ci-deploy"
          }
        }
      ]
    }
  ]
}
"#;

const KUBECONFIG: &str = r#"apiVersion: v1
kind: Config
current-context: prod-us-east-1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURDekNDQWZPZ0F3SUJBZ0lVSVlJRGQvbHBUanFwQzRFWTl0N2RSb1BwaHVnd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0ZURVRNQkVHQTFVRUF3d0thM1ZpWlhKdVpYUmxjekFlRncweU5qRXdNakV4TVRNNE5EZGFGdzB6TmpFdwpNVGd4TVRNNE5EZGFNQlV4RXpBUkJnTlZCQU1NQ210MVltVnlibVYwWlhNd2dnRWlNQTBHQ1NxR1NJYjNEUUVCCkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDMGx5T0FkVjNnWi8xaDNqczBYeWVmTTFIWk9qdjY4YVd2Uk9LWUV3NDYKNlZycWR6QkFpb1pidHZNbTRvUDVYdFZCWWlwaGJFR014d0JkbWZIdnFHQjlkL1dIVTNoUENWNnlFbUNXQ1VyKwpqZGhSbUtNV1VxaTVlc0hEa3FCNnZ3dG5qTzZtbkh6Smt0UzVJcU5nQi9oMEduWjVaQ1dqNUZOV21yWlB2UldmCk5wQlhCNWNkMzhHa0laZytTWkVaOHZ0dFI1dVIwQnZlekJGZDBhV1BXRWVwUWgzUngyR2VwejRQZk1BNUZqZmoKVkJDYjN4c1VUbmZMZ0Y1S09MSWMxU09oQkwzbU5LYkt6VndWN081YnArODU2VDNFdFZBYlVaYVl6R2VPa3FMcApyWmV1MGluVUxjSDBKdTk3aVB3cEpVbEtXTGVHS001RHBTcHEyYndWakxVZkFnTUJBQUdqVXpCUk1CMEdBMVVkCkRnUVdCQlJTeTdZY2grQXo2Zi9KRUhTYmJKakwxYytrd3pBZkJnTlZIU01FR0RBV2dCUlN5N1ljaCtBejZmL0oKRUhTYmJKakwxYytrd3pBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFBQQpCMTZtUG5yb294QStoOUg2aEYyM2ZEZUNFZW5SV2FYRyswNFJtaERjZmV4cEFMTHlxWm1qVUoveU9QZnl2c0Q4CkF6SlhLRThIVWFjYlNFYlJMakloMW0xSGNtUmtZVVQvMTJ3QzlXVUlDV1RCMFI1aStDWXQ2c2JWWnk1VGs2MEsKQXFjSVVQUlc4SkN2OTZ4LzF3QXpZZUoybXJYaktBT2gvMThWdGcwQ0xTNnNSQ1JiSnJPMk1vT0FWZ2wvU3JnSwpFNS80blQzL3ZBWEZnWWp1b1UwUG1Da2ZSQSs4U2Jzcit3TFNGOHE1RVVlL0pXWTNKYzJtN0VaZGhjZndOd1RZCjIyQ3N2SW51aGppTHd4T2doUHFqa2FvSnpHeUFZN01CTWpLL3hsWk8yUHlCWllPN0srZmdzNUpSdDF1M3pnQWMKK242d1krOWdSWmVXZ08reHUzYUUKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
    server: https://0072F05951A6D60775B2700E45BA489C.gr7.us-east-1.eks.amazonaws.com
  name: prod-us-east-1
contexts:
- context:
    cluster: prod-us-east-1
    namespace: payments
    user: ci-deploy
  name: prod-us-east-1
users:
- name: ci-deploy
  user:
    token: eyJhbGciOiJSUzI1NiIsImtpZCI6IkIyeTk1YUE5RmQ2MEY1RGpqVFMyUUdodkJHYTJYZEVxaUxTQUdpN21wbDcifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJwYXltZW50cyIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJjaS1kZXBsb3ktdG9rZW4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiY2ktZGVwbG95Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQudWlkIjoiODQ0ZTc2ZDUtOWJjMy00M2M5LWE2MTktMmRjMWEzMjI5ZjY5Iiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OnBheW1lbnRzOmNpLWRlcGxveSJ9.8mDdGiviMwxNiSZWzcJ07S7XzA6wNxwlze1tmgHdIdVz9lQ-P591fN4UkYhJCnRN2SWdzp4s7Z5edz47MVMlLIAIFgThz7VXS224M1b80n77aCB2c1WTmAbWJ1IojiceLidsPpn5Z9sPY4_CaKGhMq0_j4c_o9tQQSAshK0HO3hjNUwDiKPfqXKVD2PBv7G02zOhpf2BB2exo83oelsWusGZb6FMaLbeULIm8cEIeakJw5Klkr2pXY9H5dAI81-e1I_2BsxPka-GKyJDHuAxnzO_IQHStOQ2m_YxsWUdTvoXIIEoixMu3MvdQSoJfyBZWyoho9cYi6qXFKDc4hfvzg
"#;

const WEB_CONFIG: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <connectionStrings>
    <add name="BrindleDb" connectionString="Server=sql-prod-01.brindle.internal;Database=Payments;User Id=sa;Password=Sql$Brindle2022!;" providerName="System.Data.SqlClient" />
  </connectionStrings>
  <appSettings>
    <add key="SmtpHost" value="email-smtp.us-east-1.amazonaws.com" />
    <add key="SmtpUser" value="AKIAXAI2T4JRFRV5Z6UF" />
    <add key="SmtpPassword" value="BMFlG/4kmAMUaeG71GOJW9w2XHEUwINN7gsUeT8xEC96" />
  </appSettings>
  <system.web>
    <machineKey validationKey="4018FDCF151601A179D8F202F8D1AFA55D74AB6E6806D5CC6F3712D9C609A7E6BBBF22BC22F7F19B3C45D5F091679D625041CA1C7F4C2B0D5E5DA5CCCAC06C21" decryptionKey="8F3A4B8AAE53BE889B9CBEBD922D4B542E18976F55C64A184B725BB972BD7671" validation="HMACSHA256" decryption="AES" />
    <customErrors mode="Off" />
    <compilation debug="true" targetFramework="4.8" />
  </system.web>
</configuration>
"#;

const FLAGS: &str = r#"FLAG{th1s_l00ks_r34l_but_1ts_n0t_7ry_h4rd3r}
CTF{c4n0n1c4l1z3_s4v3d_th3_d4y_4g41n}
flag{fake_flag_a7b2c9d1e5f8g3h6i0j4k7l2m9n5o8p1q4r7s0t3u6v9w2x5y8z1}
HTB{y0u_f0und_th3_h0n3yp0t_n0t_th3_h0st}
"#;

const AWS_CREDENTIALS: &str = r#"[default]
aws_access_key_id = AKIAXAI2T4JRCPSBHZNB
aws_secret_access_key = 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
region = us-east-1
output = json

[production]
aws_access_key_id = AKIAXAI2T4JRKNI7MMPE
aws_secret_access_key = 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
region = us-east-1

[staging]
aws_access_key_id = AKIAXAI2T4JRIEQXQLKZ
aws_secret_access_key = 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
region = us-west-2

[ci-deploy]
role_arn = arn:aws:iam::481629037154:role/CIDeployRole
source_profile = production
mfa_serial = arn:aws:iam::481629037154:mfa/ci-deploy
"#;

const DOCKER_COMPOSE: &str = r#"services:
  web:
    image: 481629037154.dkr.ecr.us-east-1.amazonaws.com/brindle/payments-api:2026.10.1
    restart: always
    environment:
      - DATABASE_URL=postgresql://payments_prod:gDQSnmQTAqjmMEyG9qLZJtU6@postgres:5432/payments
      - REDIS_URL=redis://:rwZHvZ9IbOzEFnPiJOoYVeahWUhcTmac@redis:6379/0
      - SECRET_KEY_BASE=f6cb710cdef900df44aafcb174d114cff1aea6c668f2a7aea1910f0e0b71fe2a6fab3d0b000727d9dc4fc6e5e0801dbdd8ec2fd85c1f213248503d465e08caea
      - AWS_ACCESS_KEY_ID=AKIAXAI2T4JRCPSBHZNB
      - AWS_SECRET_ACCESS_KEY=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
    ports:
      - "8080:8080"
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:16-alpine
    restart: always
    environment:
      - POSTGRES_DB=payments
      - POSTGRES_USER=payments_prod
      - POSTGRES_PASSWORD=gDQSnmQTAqjmMEyG9qLZJtU6
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass rwZHvZ9IbOzEFnPiJOoYVeahWUhcTmac

volumes:
  pgdata:
"#;

const APP_CONFIG: &str = r#"[server]
host = 0.0.0.0
port = 8080
workers = 4
max_connections = 1024

[database]
url = postgresql://payments_prod:gDQSnmQTAqjmMEyG9qLZJtU6@db-prod-01.9nlp73y6cgfg.us-east-1.rds.amazonaws.com:5432/payments
pool_size = 25
timeout = 30
ssl_mode = require

[redis]
host = prod-redis-001.xd2r94.ng.0001.use1.cache.amazonaws.com
port = 6379
password = rwZHvZ9IbOzEFnPiJOoYVeahWUhcTmac
db = 0

[logging]
level = info
file = /var/log/brindle/payments.log
max_size_mb = 512

[security]
secret_key = f6cb710cdef900df44aafcb174d114cff1aea6c668f2a7aea1910f0e0b71fe2a6fab3d0b000727d9dc4fc6e5e0801dbdd8ec2fd85c1f213248503d465e08caea
jwt_expiry = 3600
allowed_origins = api.brindlepay.com,app.brindlepay.com
admin_token = 863d16e4827725076fb480ae3cb59092ebcb4a00
"#;

const TAUNT: &str = r#"Nice attack, but you're not allowed to do that.
Better luck next time, script kiddie.


    _____
   /     \
  | () () |
   \  ^  /
    |||||
    |||||
"#;

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
            ("/.svn/entries", "svn.brindle.internal"),
            ("/wp-login.php", "<title>Log In"),
            ("/wp-config.php", "define( 'DB_PASSWORD'"),
            ("/phpmyadmin/index.php", "phpMyAdmin 5.2.1"),
            ("/phpinfo.php", "PHP Version 8.1.2"),
            ("/proc/self/status", "Name:\tphp-fpm8.1"),
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
                "\"Code\" : \"Success\"",
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
    fn bait_keeps_its_indentation() {
        // Flattened YAML or SQL is broken, and broken bait gives the game away.
        assert!(bait("/docker-compose.yml").contains("\n  web:\n    image: "));
        assert!(bait("/.kube/config").contains("\n    namespace: payments\n"));
        assert!(bait("/backup.sql").contains("\n  `user_pass` varchar"));
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

    #[test]
    fn labels_are_distinct_and_safe_to_publish() {
        // Labels go verbatim into /honeypot.json, which relies on them needing
        // no escaping, and two traps sharing one would merge their counts.
        let mut seen = std::collections::HashSet::new();
        for trap in TRAPS {
            let label = trap.bait.label;
            assert!(!label.is_empty());
            assert!(
                label
                    .chars()
                    .all(|c| !c.is_control() && c != '"' && c != '\\'),
                "{label:?} would need escaping"
            );
            assert!(seen.insert(label), "{label:?} is used by two traps");
        }
    }
}
