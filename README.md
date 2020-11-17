# sasl2-http

Cyrus-SASL/libsasl2 auxprop plugin using HTTP to query information

imapd.conf settings
-------------------

- `sasl_httpdb_url`: backend URL

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
