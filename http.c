// HTTP client plugin for libsasl2
// Copyright © 2020 Mildred
// MIT license

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sasl/sasl.h>
#include <sasl/saslutil.h>
#include <sasl/saslplug.h>
#include <sasl/prop.h>

#include <curl/curl.h>

#include "plugin_common.h"

typedef struct httpdb_settings {
    CURL *curl;
    const char *url;
} httpdb_settings_t;

typedef struct writedata {
    char   *response;
    size_t  size;
} writedata_t;

static size_t writedata(void *data, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    writedata_t *mem = (writedata_t *)userp;

    char *ptr = realloc(mem->response, mem->size + realsize + 1);
    if(ptr == NULL)
        return 0;  /* out of memory! */

    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), data, realsize);
    mem->size += realsize;
    mem->response[mem->size] = 0;

    return realsize;
}

static _Bool add_param(CURL *curl, char **params, int *params_len, const char *name, const char *value) {
  _Bool result = 1;
  char *esc_name = curl_easy_escape(curl, name, 0);
  char *esc_value = curl_easy_escape(curl, value, 0);
  int new_params_len = *params_len + 1 + strlen(esc_name) + 1 + strlen(esc_value);
  char *new_params = malloc(new_params_len * sizeof(char));
  if(new_params) {
    if(*params_len == 0) {
      snprintf(new_params, new_params_len, "%s=%s", esc_name, esc_value);
    } else {
      snprintf(new_params, new_params_len, "%s&%s=%s", *params, esc_name, esc_value);
    }
    if(*params) free(*params);
    *params = new_params;
    *params_len = new_params_len;
  } else {
    result = 0;
  }
  curl_free(esc_name);
  curl_free(esc_value);
  return result;
}

static int httpdb_auxprop_lookup(void *glob_context,
                                 sasl_server_params_t *sparams,
                                 unsigned flags,
                                 const char *user,
                                 unsigned ulen)
{
    char *userid = NULL;
    /* realm could be used for something clever */
    char *realm = NULL;
    const char *user_realm = NULL;
    const struct propval *to_fetch, *cur;
    size_t value_len;
    char *user_buf;
    char *query = NULL;
    char *escap_userid = NULL;
    char *escap_realm = NULL;
    httpdb_settings_t *settings;
    int verify_against_hashed_password;
    void *conn = NULL;
    int ret;

    if (!glob_context || !sparams || !user) return SASL_BADPARAM;

    /* setup the settings */
    settings = (httpdb_settings_t *)glob_context;
    if (!settings) return SASL_BADPARAM;

    sparams->utils->log(sparams->utils->conn, SASL_LOG_DEBUG,
                        "httpdb plugin Parse the username %s\n", user);

    user_buf = sparams->utils->malloc(ulen + 1);
    if (!user_buf) {
        ret = SASL_NOMEM;
        goto done;
    }

    memcpy(user_buf, user, ulen);
    user_buf[ulen] = '\0';

    if(sparams->user_realm) {
        user_realm = sparams->user_realm;
    } else {
        user_realm = sparams->serverFQDN;
    }

    if ((ret = _plug_parseuser(sparams->utils,
                               &userid,
                               &realm,
                               user_realm,
                               sparams->serverFQDN,
                               user_buf)) != SASL_OK ) {
        goto done;
    }

    /*************************************/

    /* find out what we need to get */
    /* this corrupts const char *user */
    to_fetch = sparams->utils->prop_get(sparams->propctx);
    if (!to_fetch) {
        ret = SASL_NOMEM;
        goto done;
    }

    char *body = 0;
    int body_len = 0;

    if(!add_param(settings->curl, &body, &body_len, "req", "lookup") ||
       !add_param(settings->curl, &body, &body_len, "userid", userid) ||
       !add_param(settings->curl, &body, &body_len, "realm", realm)) {
        ret = SASL_NOMEM;
        goto done;
    }
    sparams->utils->log(sparams->utils->conn, SASL_LOG_DEBUG,
                        "httpdb plugin lookup userid=%s, realm=%s\n",
                        userid, realm);

    verify_against_hashed_password = flags & SASL_AUXPROP_VERIFY_AGAINST_HASH;

    /* Assume that nothing is found */
    ret = SASL_NOUSER;
    for (cur = to_fetch; cur->name; cur++) {
        char *realname = (char *) cur->name;

        /* Only look up properties that apply to this lookup! */
        if (cur->name[0] == '*'
            && (flags & SASL_AUXPROP_AUTHZID))
            continue;
        if (!(flags & SASL_AUXPROP_AUTHZID)) {
            if(cur->name[0] != '*')
                continue;
            else
                realname = (char*)cur->name + 1;
        }

        /* If it's there already, we want to see if it needs to be
         * overridden. userPassword is a special case, because it's value
           is always present if SASL_AUXPROP_VERIFY_AGAINST_HASH is specified.
           When SASL_AUXPROP_VERIFY_AGAINST_HASH is set, we just clear userPassword. */
        if (cur->values && !(flags & SASL_AUXPROP_OVERRIDE) &&
            (verify_against_hashed_password == 0 ||
             strcasecmp(realname, SASL_AUX_PASSWORD_PROP) != 0)) {
            continue;
        } else if (cur->values) {
            sparams->utils->prop_erase(sparams->propctx, cur->name);
        }

        sparams->utils->log(sparams->utils->conn, SASL_LOG_DEBUG,
                            "httpdb plugin lookup param=%s\n",
                            realname);

        if(!add_param(settings->curl, &body, &body_len, "param", realname)) {
            ret = SASL_NOMEM;
            goto done;
        }
    }

    writedata_t response;
    bzero(&response, sizeof(response));

    curl_easy_setopt(settings->curl, CURLOPT_WRITEFUNCTION, writedata);
    curl_easy_setopt(settings->curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(settings->curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(settings->curl, CURLOPT_URL, settings->url);
    ret = curl_easy_perform(settings->curl);
    if(ret != CURLE_OK) {
        sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
                            "httpdb plugin couldn't connect to %s: %s\n",
                            settings->url, curl_easy_strerror(ret));
        ret = SASL_FAIL;
        goto done;
    }

    long code;
    curl_easy_getinfo(settings->curl, CURLINFO_RESPONSE_CODE, &code);
    if (code < 200 || code >= 300) {
        sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
                            "httpdb plugin HTTP error code %d on %s\n",
                            code, settings->url);
        ret = SASL_FAIL;
        goto done;
    }


    ret = SASL_OK;

    char *key = NULL;
    char *value = NULL;
    for(int i = 0; i < response.size; ++i) {
        char c = response.response[i];
        if (!key) key = &response.response[i];
        else if (!value) value = &response.response[i];

        switch(c) {
            case '=':
                response.response[i] = 0;
                value = NULL;
                break;
            case '&':
                response.response[i] = 0;

                int keylen, valuelen;
                char *key2 = curl_easy_unescape(settings->curl, key, 0, &keylen);
                char *value2 = curl_easy_unescape(settings->curl, value, 0, &valuelen);

                if(strstr(key2, "param.") == key2) {
                    sparams->utils->prop_set(sparams->propctx, &key2[6], value2, valuelen);
                    sparams->utils->log(sparams->utils->conn, SASL_LOG_DEBUG,
                                        "httpdb plugin lookup got param %s=%s: %s\n",
                                        &key2[6], value2);
                } else {
                    sparams->utils->log(sparams->utils->conn, SASL_LOG_DEBUG,
                                        "httpdb plugin lookup got discarded %s=%s: %s\n",
                                        key2, value2);
                }

                curl_free(key2);
                curl_free(value2);

                key = NULL;
                value = NULL;
                break;
            default:
                break;
        }
    }

    if (flags & SASL_AUXPROP_AUTHZID) {
        /* This is a lie, but the caller can't handle
           when we return SASL_NOUSER for authorization identity lookup. */
        if (ret == SASL_NOUSER) {
            ret = SASL_OK;
        }
    }


  done:
    if (userid) sparams->utils->free(userid);
    if (realm) sparams->utils->free(realm);
    if (user_buf) sparams->utils->free(user_buf);
    if (body) free(body);
    if (response.response) free(response.response);

    return (ret);
}

static int httpdb_auxprop_store(void *glob_context,
                             sasl_server_params_t *sparams,
                             struct propctx *ctx,
                             const char *user,
                             unsigned ulen)
{
    char *userid = NULL;
    char *realm = NULL;
    const char *user_realm = NULL;
    int ret = SASL_FAIL;
    const struct propval *to_store, *cur;
    char *user_buf;
    char *statement = NULL;
    const char *cmd;
    void *conn = NULL;

    /* setup the settings */
    httpdb_settings_t *settings = (httpdb_settings_t *)glob_context;
    if (!settings) return SASL_BADPARAM;

    /* make sure our input is okay */
    if (!glob_context || !sparams || !user) return SASL_BADPARAM;

    sparams->utils->log(sparams->utils->conn, SASL_LOG_DEBUG,
                        "httpdb plugin Parse the username %s\n", user);

    user_buf = sparams->utils->malloc(ulen + 1);
    if (!user_buf) {
        ret = SASL_NOMEM;
        goto done;
    }

    memcpy(user_buf, user, ulen);
    user_buf[ulen] = '\0';

    if (sparams->user_realm) {
        user_realm = sparams->user_realm;
    }
    else {
        user_realm = sparams->serverFQDN;
    }

    ret = _plug_parseuser(sparams->utils, &userid, &realm, user_realm,
                          sparams->serverFQDN, user_buf);
    if (ret != SASL_OK)        goto done;

    to_store = sparams->utils->prop_get(ctx);

    if (!to_store) {
        ret = SASL_BADPARAM;
        goto done;
    }

    char *body = 0;
    int body_len = 0;

    if(!add_param(settings->curl, &body, &body_len, "req", "store") ||
       !add_param(settings->curl, &body, &body_len, "userid", userid) ||
       !add_param(settings->curl, &body, &body_len, "realm", realm)) {
        ret = SASL_NOMEM;
        goto done;
    }

    sparams->utils->log(sparams->utils->conn, SASL_LOG_DEBUG,
                        "httpdb plugin store userid=%s realm=%s\n",
                        userid, realm);

    for (cur = to_store; ret == SASL_OK && cur->name; cur++) {

        if (cur->name[0] == '*') {
            continue;
        }

        int keylen = strlen(cur->name) + 1024;
        char key2[keylen];
        snprintf(key2, keylen, "param.%s", cur->name);

        const char *value = cur->values && cur->values[0] ? cur->values[0] : "";

        sparams->utils->log(sparams->utils->conn, SASL_LOG_DEBUG,
                            "httpdb plugin store %s=%s\n",
                            key2, value);
        if(!add_param(settings->curl, &body, &body_len, key2, value)) {
            ret = SASL_NOMEM;
            goto done;
        }
    }

    curl_easy_setopt(settings->curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(settings->curl, CURLOPT_URL, settings->url);
    ret = curl_easy_perform(settings->curl);
    if(ret != CURLE_OK) {
        sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
                            "httpdb plugin couldn't connect to %s: %s\n",
                            settings->url, curl_easy_strerror(ret));
        ret = SASL_FAIL;
        goto done;
    }

    long code;
    curl_easy_getinfo(settings->curl, CURLINFO_RESPONSE_CODE, &code);
    if (code < 200 || code >= 300) {
        sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
                            "httpdb plugin HTTP error code %d on %s\n",
                            code, settings->url);
        ret = SASL_FAIL;
        goto done;
    }

  done:
    if (userid) sparams->utils->free(userid);
    if (realm) sparams->utils->free(realm);
    if (user_buf) sparams->utils->free(user_buf);
    if (body) free(body);

    return ret;
}

static void httpdb_auxprop_free(void *glob_context, const sasl_utils_t *utils)
{
    httpdb_settings_t *settings = (httpdb_settings_t *)glob_context;
    if (!settings) return;

    utils->log(utils->conn, SASL_LOG_DEBUG, "httpdb: free\n");

    if (settings->curl) {
        curl_easy_cleanup(settings->curl);
    }

    utils->free(settings);
}

static void httpdb_get_settings(const sasl_utils_t *utils, void *glob_context)
{
    httpdb_settings_t *settings = (httpdb_settings_t *) glob_context;

    settings->curl = curl_easy_init();

    int r = utils->getopt(utils->getopt_context, "httpdb", "httpdb_url", &settings->url, NULL);
    if (r || !settings->url ) {
        settings->url = NULL;
    }
}

static sasl_auxprop_plug_t httpdb_auxprop_plugin = {
    0,                           /* Features */
    0,                           /* spare */
    NULL,                        /* glob_context */
    httpdb_auxprop_free,         /* auxprop_free */
    httpdb_auxprop_lookup,       /* auxprop_lookup */
    "httpdb",                    /* name */
    httpdb_auxprop_store         /* auxprop_store */
};

int httpdb_auxprop_plug_init(sasl_utils_t *utils,
                            int max_version,
                            int *out_version,
                            sasl_auxprop_plug_t **plug,
                            const char *plugname __attribute__((unused)))
{
    if(!out_version || !plug) return SASL_BADPARAM;

    utils->log(utils->conn, SASL_LOG_DEBUG, "httpdb: starting up...\n");

    /* Check if libsasl API is older than ours. If it is, fail */
    if(max_version < SASL_AUXPROP_PLUG_VERSION) {
        utils->log(utils->conn, SASL_LOG_ERR, "httpdb: version mismatch %d < %d\n",
            max_version, SASL_AUXPROP_PLUG_VERSION);
        return SASL_BADVERS;
    }
    *out_version = SASL_AUXPROP_PLUG_VERSION;

    httpdb_settings_t *settings = (httpdb_settings_t *) utils->malloc(sizeof(httpdb_settings_t));
    bzero(settings, sizeof(httpdb_settings_t));

    if (!settings) {
        utils->log(utils->conn, SASL_LOG_ERR, "httpdb: failed to initialize\n");
        MEMERROR(utils);
        return SASL_NOMEM;
    }

    httpdb_get_settings(utils, settings);

    if (!settings->curl) {
        utils->log(utils->conn, SASL_LOG_ERR, "httpdb: failed to initialize curl\n");
        httpdb_auxprop_free(settings, utils);
        MEMERROR(utils);
        return SASL_NOMEM;
    }

    if (!settings->url) {
        utils->log(utils->conn, SASL_LOG_ERR, "httpdb: missing httpdb_url setting\n");
        httpdb_auxprop_free(settings, utils);
        return SASL_BADPARAM;
    }

    httpdb_auxprop_plugin.glob_context = settings;
    *plug = &httpdb_auxprop_plugin;

    utils->log(utils->conn, SASL_LOG_DEBUG, "httpdb: initialized\n");

    return SASL_OK;
}

int httpdb_client_plug_init(sasl_utils_t *utils,
                            int max_version,
                            int *out_version,
                            sasl_auxprop_plug_t **plug,
                            const char *plugname __attribute__((unused)))
{
    return SASL_FAIL;
}

int httpdb_server_plug_init(sasl_utils_t *utils,
                            int max_version,
                            int *out_version,
                            sasl_auxprop_plug_t **plug,
                            const char *plugname __attribute__((unused)))
{
    return SASL_FAIL;
}

int httpdb_canonuser_plug_init(sasl_utils_t *utils,
                               int max_version,
                               int *out_version,
                               sasl_auxprop_plug_t **plug,
                               const char *plugname __attribute__((unused)))
{
    return SASL_FAIL;
}

