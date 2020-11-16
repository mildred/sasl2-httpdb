
CFLAGS = -Wall -Wextra -Wshadow -Werror -g

libsaslhttpdb.so: http.c http_init.c plugin_common.c plugin_common.h config.h
	$(CC) -lcurl -o $@ -shared -I. -I/usr/include/sasl -fPIC $+
