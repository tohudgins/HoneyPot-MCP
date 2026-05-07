"""Fake HTML response templates for the HTTP honeypot.

Extracted from `http.py` and expanded for variety — the original 5
templates meant any scanner hitting two honeypots saw identical content.
Now there are multiple variants per category (different phpMyAdmin
versions, different framework `.env` files, multiple admin UIs) so the
content itself is harder to fingerprint as canned.

Templates are kept persona-independent — what fakes a Laravel `.env`
doesn't change because the server header says Nginx instead of Apache.
The persona module owns headers and 404s; this module owns body content.
"""

from __future__ import annotations


_TEMPLATES: dict[str, str] = {
    # ── Admin panel variants ──────────────────────────────────────────────────
    "admin_panel": """<!DOCTYPE html><html><head><title>Admin Login</title>
<style>body{font-family:Arial,sans-serif;background:#f4f4f4}.box{background:#fff;padding:2rem;max-width:360px;margin:5rem auto;border-radius:6px;box-shadow:0 2px 8px rgba(0,0,0,.1)}</style>
</head><body><div class="box">
<h2>Administrator Sign In</h2>
<form method="POST" action="/admin">
<p>Username<br><input name="username" style="width:100%"></p>
<p>Password<br><input type="password" name="password" style="width:100%"></p>
<p><button type="submit">Login</button></p>
</form></div></body></html>""",

    "cpanel_login": """<!DOCTYPE html><html><head><title>cPanel Login</title>
<meta charset="utf-8"></head><body style="background:#001f3f;color:#fff;font-family:Arial">
<div style="max-width:380px;margin:6rem auto;background:#fff;color:#000;padding:1.5rem;border-radius:8px">
<h2 style="color:#001f3f">cPanel</h2>
<form method="POST" action="/admin">
<input name="user" placeholder="Username" style="width:100%;margin-bottom:.5rem;padding:.5rem"><br>
<input type="password" name="pass" placeholder="Password" style="width:100%;margin-bottom:1rem;padding:.5rem"><br>
<button type="submit" style="width:100%;background:#FF4136;color:#fff;border:0;padding:.7rem">Log in</button>
</form></div></body></html>""",

    "webmin_login": """<!DOCTYPE html><html><head><title>Login to Webmin</title></head>
<body bgcolor="#9999cc"><center>
<h1>Login to Webmin</h1>
<form method="POST" action="/session_login.cgi">
<table><tr><td>Username</td><td><input name="user"></td></tr>
<tr><td>Password</td><td><input type="password" name="pass"></td></tr>
<tr><td colspan="2"><center><input type="submit" value="Login"></center></td></tr></table>
</form></center></body></html>""",

    # ── Database admin variants ───────────────────────────────────────────────
    "phpmyadmin_5": """<!DOCTYPE html><html><head><title>phpMyAdmin</title>
<meta charset="utf-8"></head><body>
<div style="max-width:480px;margin:4rem auto;text-align:center;font-family:Arial">
<h1>phpMyAdmin 5.2.1</h1>
<p>Welcome to phpMyAdmin</p>
<form method="POST" action="/index.php">
<p>Server: <select><option>localhost</option></select></p>
<p>Username: <input name="pma_username" value="root"></p>
<p>Password: <input type="password" name="pma_password"></p>
<p>Database: <input name="db" value=""></p>
<button type="submit">Go</button>
</form></div></body></html>""",

    "phpmyadmin_4": """<!DOCTYPE html><html><head><title>phpMyAdmin</title></head>
<body><div style="max-width:420px;margin:4rem auto;text-align:center">
<h1>phpMyAdmin 4.9.5</h1>
<form method="POST" action="/index.php">
Username <input name="pma_username" value="root"><br>
Password <input type="password" name="pma_password"><br>
<button type="submit">Go</button>
</form></div></body></html>""",

    # ── CMS admin variants ────────────────────────────────────────────────────
    "wordpress_admin": """<!DOCTYPE html><html><head><title>Log In &lsaquo; WordPress</title>
<meta charset="utf-8"></head><body class="login">
<div id="login" style="max-width:320px;margin:5rem auto">
<h1><a href="/">WordPress</a></h1>
<form name="loginform" method="post" action="/wp-login.php">
<p><label>Username or Email Address</label><br>
<input name="log" id="user_login" type="text" style="width:100%"></p>
<p><label>Password</label><br>
<input name="pwd" id="user_pass" type="password" style="width:100%"></p>
<p><input type="checkbox" name="rememberme"> Remember Me</p>
<p><input type="submit" value="Log In" style="width:100%"></p>
</form></div></body></html>""",

    "joomla_admin": """<!DOCTYPE html><html><head><title>Joomla! Administration Login</title></head>
<body><div style="max-width:340px;margin:5rem auto;font-family:Arial">
<h2>Joomla! Administrator</h2>
<form method="POST" action="/administrator/index.php">
<p>Username <input name="username"></p>
<p>Password <input type="password" name="passwd"></p>
<button type="submit">Log in</button>
</form></div></body></html>""",

    # ── Fake env files ────────────────────────────────────────────────────────
    "env_laravel": """APP_NAME=Laravel
APP_ENV=production
APP_KEY=base64:rAndOmKeyHerE1234567890==
APP_DEBUG=false
APP_URL=https://app.example.com

LOG_CHANNEL=stack
LOG_LEVEL=error

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=production_db
DB_USERNAME=root
DB_PASSWORD=SuperSecret123!

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=production-uploads
""",

    "env_rails": """RAILS_ENV=production
SECRET_KEY_BASE=8f7c6b5a4d3c2b1a0f9e8d7c6b5a4d3c2b1a0f9e8d7c6b5a4d3c2b1a
DATABASE_URL=postgres://railsapp:HunteRailsPwd_99@db.internal:5432/rails_prod

REDIS_URL=redis://:redispass2024@redis.internal:6379/0
SIDEKIQ_REDIS_URL=redis://:redispass2024@redis.internal:6379/1

AWS_ACCESS_KEY_ID=AKIA4NJ7IM3CYRX3XGZP
AWS_SECRET_ACCESS_KEY=fakeSecretKeyHere1234567890qwertyuiopasdf
AWS_REGION=us-west-2
AWS_S3_BUCKET=rails-prod-assets

STRIPE_SECRET_KEY=sk_live_51HxxXxXxXxXxXxXxXxXxXxXxX
SENDGRID_API_KEY=SG.fakeSendGridKey1234567890.aBcDeFgHiJkLmNoPqRsTu
""",

    "env_node": """NODE_ENV=production
PORT=3000
JWT_SECRET=production_jwt_secret_KEEP_PRIVATE_2024
SESSION_SECRET=session_secret_random_string_here

MONGO_URI=mongodb://app_user:MongoPwd2024@mongo.internal:27017/app_prod
REDIS_URL=redis://:r3disPwd!@redis.internal:6379

GOOGLE_CLIENT_ID=1234567890-abcdefghijklmnop.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-fakeGoogleClientSecret123
GITHUB_CLIENT_ID=Iv1.a1b2c3d4e5f6g7h8
GITHUB_CLIENT_SECRET=fakeGitHubSecret9876543210abcdef

STRIPE_SECRET_KEY=sk_live_51HxxX_fakeStripeKey_X
SENDGRID_API_KEY=SG.fakeNodeSendGridKey.RandomString
""",

    # ── Generic ───────────────────────────────────────────────────────────────
    "generic_login": """<!DOCTYPE html><html><head><title>Login</title></head><body>
<div style="max-width:340px;margin:5rem auto;font-family:Arial">
<h2>Please Login</h2>
<form method="POST">
Username: <input name="username"><br>
Password: <input type="password" name="password"><br>
<input type="submit" value="Login">
</form></div></body></html>""",
}


def get_template(name: str) -> str:
    """Look up a template by name. Falls back to generic_login if missing —
    a misconfigured endpoint shouldn't 500 the honeypot."""
    return _TEMPLATES.get(name, _TEMPLATES["generic_login"])


def all_template_names() -> list[str]:
    return list(_TEMPLATES.keys())
