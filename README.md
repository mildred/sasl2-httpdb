sasl2-httpdb
============

Cyrus-SASL/libsasl2 auxprop plugin using HTTP to query information

imapd.conf settings
-------------------

- `sasl_httpdb_url`: backend URL

Protocol
--------

On the URL configured, the plugin will perform a POST query with
`application/x-www-form-urlencoded` payload. The payload contains different
variables depending on the type of query performed.

- lookup queries:

    - `req=lookup`
    - `userid=` the user ID
    - `realm=` the realm
    - `param=` the param requested, repeated for each param requested

    The response should contain a `application/x-www-form-urlencoded` payload
    with a 2xx status code. The response should contain:

    - 'res=' which must be `ok` when the user was found (even if no param was
      requested)
    - `param.<paramname>=` containing the value of each param requested

- store queries:

    - `req=store`
    - `userid=` the user ID
    - `realm=` the realm
    - `param.<paramname>=` the param with its value to store

    The response must have a 2xx code to succeed. The body can be empty.


installation
------------

With terraform:

```hcl

resource "sys_package" "httpdb" {
  for_each = toset( ["build-essential", "libcurl4-openssl-dev", "libsasl2-dev", "git"] )
  type = "deb"
  name = each.key
}

resource "sys_dir" "httpdb" {
  path           = "/usr/src/sasl2-httpdb"
  allow_existing = true
}

resource "sys_shell_script" "httpdb" {
  depends_on = [ sys_package.httpdb ]
  working_directory = sys_dir.httpdb.path
  create = <<SCRIPT
  (
    git init
    git fetch https://github.com/mildred/sasl2-httpdb
    git checkout -f FETCH_HEAD
    make
    cp libhttpdb.so /usr/lib/x86_64-linux-gnu/sasl2/libhttpdb.so
  ) >&2
  sha1sum /usr/lib/x86_64-linux-gnu/sasl2/libhttpdb.so
SCRIPT
  read = <<SCRIPT
  sha1sum /usr/lib/x86_64-linux-gnu/sasl2/libhttpdb.so || true
SCRIPT
  delete = <<SCRIPT
  rm -f /usr/lib/x86_64-linux-gnu/sasl2/libhttpdb.so
SCRIPT
}

#resource "sys_file" "libsaslhttpdb" {
#  filename        = "/usr/lib/x86_64-linux-gnu/sasl2/libsaslhttpdb.so"
#  source          = "https://github.com/mildred/sasl2-httpdb/releases/download/latest-master/libsaslhttpdb.so"
#  file_permission = 0755
#}

```

build
-----

Requires libcurl and libsasl2. Run:

    make

debug
-----

imapd.conf

```yaml
debug: 1

# SASL_LOG_NONE  0 don't log anything
# SASL_LOG_ERR   1 log unusual errors (default)
# SASL_LOG_FAIL  2 log all authentication failures
# SASL_LOG_WARN  3 log non-fatal warnings
# SASL_LOG_NOTE  4 more verbose than LOG_WARN
# SASL_LOG_DEBUG 5 more verbose than LOG_NOTE
# SASL_LOG_TRACE 6 traces of internal protocols
# SASL_LOG_PASS  7 traces of internal protocols, including passwords
sasl_log_level: 7

allowplaintext: yes
sasl_pwcheck_method: auxprop
sasl_auto_transition: yes
sasl_auxprop_plugin: httpdb

sasl_httpdb_url: http://localhost/

```

Run:

    cyrus imtest -u jdoe@example.com -w dogood
