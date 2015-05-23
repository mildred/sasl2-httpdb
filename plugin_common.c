/* Generic SASL plugin utility functions
 * Rob Siemborski
 * $Id: plugin_common.c,v 1.22 2011/09/01 14:12:18 mel Exp $
 */
/* 
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>
#include <sasl/saslplug.h>

#include <string.h>

#include "plugin_common.h"

/* Basically a conditional call to realloc(), if we need more */
int _plug_buf_alloc(const sasl_utils_t *utils, char **rwbuf,
		    unsigned *curlen, unsigned newlen) 
{
    if(!utils || !rwbuf || !curlen) {
	PARAMERROR(utils);
	return SASL_BADPARAM;
    }

    if(!(*rwbuf)) {
	*rwbuf = utils->malloc(newlen);
	if (*rwbuf == NULL) {
	    *curlen = 0;
	    MEMERROR(utils);
	    return SASL_NOMEM;
	}
	*curlen = newlen;
    } else if(*rwbuf && *curlen < newlen) {
	unsigned needed = 2*(*curlen);

	while(needed < newlen)
	    needed *= 2;

	*rwbuf = utils->realloc(*rwbuf, needed);
	if (*rwbuf == NULL) {
	    *curlen = 0;
	    MEMERROR(utils);
	    return SASL_NOMEM;
	}
	*curlen = needed;
    } 

    return SASL_OK;
}

void _plug_free_secret(const sasl_utils_t *utils, sasl_secret_t **secret) 
{
    if(!utils || !secret || !(*secret)) return;

    utils->erasebuffer((char *)(*secret)->data, (*secret)->len);
    utils->free(*secret);
    *secret = NULL;
}

/* 
 * Trys to find the prompt with the lookingfor id in the prompt list
 * Returns it if found. NULL otherwise
 */
sasl_interact_t *_plug_find_prompt(sasl_interact_t **promptlist,
				   unsigned int lookingfor)
{
    sasl_interact_t *prompt;

    if (promptlist && *promptlist) {
	for (prompt = *promptlist; prompt->id != SASL_CB_LIST_END; ++prompt) {
	    if (prompt->id==lookingfor)
		return prompt;
	}
    }

    return NULL;
}

/*
 * Retrieve the simple string given by the callback id.
 */
int _plug_get_simple(const sasl_utils_t *utils, unsigned int id, int required,
		     const char **result, sasl_interact_t **prompt_need)
{

    int ret = SASL_FAIL;
    sasl_getsimple_t *simple_cb;
    void *simple_context;
    sasl_interact_t *prompt;

    *result = NULL;

    /* see if we were given the result in the prompt */
    prompt = _plug_find_prompt(prompt_need, id);
    if (prompt != NULL) {
	/* We prompted, and got.*/
	
	if (required && !prompt->result) {
	    SETERROR(utils, "Unexpectedly missing a prompt result");
	    return SASL_BADPARAM;
	}

	*result = prompt->result;
	return SASL_OK;
    }
  
    /* Try to get the callback... */
    ret = utils->getcallback(utils->conn, id, (sasl_callback_ft *)&simple_cb, &simple_context);

    if (ret == SASL_FAIL && !required)
	return SASL_OK;

    if (ret == SASL_OK && simple_cb) {
	ret = simple_cb(simple_context, id, result, NULL);
	if (ret != SASL_OK)
	    return ret;

	if (required && !*result) {
	    PARAMERROR(utils);
	    return SASL_BADPARAM;
	}
    }
  
    return ret;
}

/*
 * Retrieve the user password.
 */
int _plug_get_password(const sasl_utils_t *utils, sasl_secret_t **password,
		       unsigned int *iscopy, sasl_interact_t **prompt_need)
{
    int ret = SASL_FAIL;
    sasl_getsecret_t *pass_cb;
    void *pass_context;
    sasl_interact_t *prompt;

    *password = NULL;
    *iscopy = 0;

    /* see if we were given the password in the prompt */
    prompt = _plug_find_prompt(prompt_need, SASL_CB_PASS);
    if (prompt != NULL) {
	/* We prompted, and got.*/
	
	if (!prompt->result) {
	    SETERROR(utils, "Unexpectedly missing a prompt result");
	    return SASL_BADPARAM;
	}
      
	/* copy what we got into a secret_t */
	*password = (sasl_secret_t *) utils->malloc(sizeof(sasl_secret_t) +
						    prompt->len + 1);
	if (!*password) {
	    MEMERROR(utils);
	    return SASL_NOMEM;
	}
      
	(*password)->len=prompt->len;
	memcpy((*password)->data, prompt->result, prompt->len);
	(*password)->data[(*password)->len]=0;

	*iscopy = 1;

	return SASL_OK;
    }

    /* Try to get the callback... */
    ret = utils->getcallback(utils->conn, SASL_CB_PASS,
			     (sasl_callback_ft *)&pass_cb, &pass_context);

    if (ret == SASL_OK && pass_cb) {
	ret = pass_cb(utils->conn, pass_context, SASL_CB_PASS, password);
	if (ret != SASL_OK)
	    return ret;

	if (!*password) {
	    PARAMERROR(utils);
	    return SASL_BADPARAM;
	}
    }

    return ret;
}

/*
 * Make the requested prompts. (prompt==NULL means we don't want it)
 */
int _plug_make_prompts(const sasl_utils_t *utils,
		       sasl_interact_t **prompts_res,
		       const char *user_prompt, const char *user_def,
		       const char *auth_prompt, const char *auth_def,
		       const char *pass_prompt, const char *pass_def,
		       const char *echo_chal,
		       const char *echo_prompt, const char *echo_def,
		       const char *realm_chal,
		       const char *realm_prompt, const char *realm_def)
{
    int num = 1;
    int alloc_size;
    sasl_interact_t *prompts;

    if (user_prompt) num++;
    if (auth_prompt) num++;
    if (pass_prompt) num++;
    if (echo_prompt) num++;
    if (realm_prompt) num++;

    if (num == 1) {
	SETERROR( utils, "make_prompts() called with no actual prompts" );
	return SASL_FAIL;
    }

    alloc_size = sizeof(sasl_interact_t)*num;
    prompts = utils->malloc(alloc_size);
    if (!prompts) {
	MEMERROR( utils );
	return SASL_NOMEM;
    }
    memset(prompts, 0, alloc_size);
  
    *prompts_res = prompts;

    if (user_prompt) {
	(prompts)->id = SASL_CB_USER;
	(prompts)->challenge = "Authorization Name";
	(prompts)->prompt = user_prompt;
	(prompts)->defresult = user_def;

	prompts++;
    }

    if (auth_prompt) {
	(prompts)->id = SASL_CB_AUTHNAME;
	(prompts)->challenge = "Authentication Name";
	(prompts)->prompt = auth_prompt;
	(prompts)->defresult = auth_def;

	prompts++;
    }

    if (pass_prompt) {
	(prompts)->id = SASL_CB_PASS;
	(prompts)->challenge = "Password";
	(prompts)->prompt = pass_prompt;
	(prompts)->defresult = pass_def;

	prompts++;
    }

    if (echo_prompt) {
	(prompts)->id = SASL_CB_ECHOPROMPT;
	(prompts)->challenge = echo_chal;
	(prompts)->prompt = echo_prompt;
	(prompts)->defresult = echo_def;

	prompts++;
    }

    if (realm_prompt) {
	(prompts)->id = SASL_CB_GETREALM;
	(prompts)->challenge = realm_chal;
	(prompts)->prompt = realm_prompt;
	(prompts)->defresult = realm_def;

	prompts++;
    }

    /* add the ending one */
    (prompts)->id = SASL_CB_LIST_END;
    (prompts)->challenge = NULL;
    (prompts)->prompt = NULL;
    (prompts)->defresult = NULL;

    return SASL_OK;
}
