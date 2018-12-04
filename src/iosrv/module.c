/**
 * (C) Copyright 2016 Intel Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * GOVERNMENT LICENSE RIGHTS-OPEN SOURCE SOFTWARE
 * The Government's rights to use, modify, reproduce, release, perform, display,
 * or disclose this software are subject to the terms of the Apache License as
 * provided in Contract No. B609815.
 * Any reproduction of computer software, computer software documentation, or
 * portions thereof marked with this legend must also reproduce the markings.
 */
/**
 * This file is part of the DAOS server. It implements the modular interface
 * to load server-side code on demand. DAOS modules are effectively dynamic
 * libraries loaded on-the-fly in the DAOS server via dlopen(3).
 */
#define D_LOGFAC       DD_FAC(server)

#include <dlfcn.h>

#include <daos_errno.h>
#include <daos/common.h>
#include <gurt/list.h>
#include <daos/rpc.h>

#include "srv_internal.h"

/* Loaded module instance */
struct loaded_mod {
	/* library handle grabbed with dlopen(3) */
	void			*lm_hdl;
	/* module interface looked up via dlsym(3) */
	struct dss_module	*lm_dss_mod;
	/* linked list of loaded module */
	d_list_t		 lm_lk;
};

/* Track list of loaded modules */
D_LIST_HEAD(loaded_mod_list);
pthread_mutex_t loaded_mod_list_lock = PTHREAD_MUTEX_INITIALIZER;

static struct loaded_mod *
dss_module_search(const char *modname)
{
	struct loaded_mod *mod;

	/* search for the module in the loaded module list */
	d_list_for_each_entry(mod, &loaded_mod_list, lm_lk) {
		if (strcmp(mod->lm_dss_mod->sm_name, modname) == 0)
			return mod;
	}

	/* not found */
	return NULL;
}

#define DSS_MODNAME_MAX_LEN	32

int
dss_module_load(const char *modname, uint64_t *mod_facs)
{
	struct loaded_mod	*lmod;
	struct dss_module	*smod;
	char			 name[DSS_MODNAME_MAX_LEN + 8];
	void			*handle;
	char			*err;
	int			 rc;

	if (strlen(modname) > DSS_MODNAME_MAX_LEN) {
		D_ERROR("modname %s is too long > %d\n",
			modname, DSS_MODNAME_MAX_LEN);
		return -DER_INVAL;
	}

	/* load the dynamic library */
	sprintf(name, "lib%s.so", modname);
	handle = dlopen(name, RTLD_LAZY | RTLD_GLOBAL);
	if (handle == NULL) {
		D_ERROR("cannot load %s: %s\n", name, dlerror());
		return -DER_INVAL;
	}

	/* allocate data structure to track this module instance */
	D_ALLOC_PTR(lmod);
	if (!lmod)
		D_GOTO(err_hdl, rc = -DER_NOMEM);

	lmod->lm_hdl = handle;

	/* clear existing errors, if any */
	dlerror();

	/* lookup the dss_module structure defining the module interface */
	sprintf(name, "%s_module", modname);
	smod = (struct dss_module *)dlsym(handle, name);

	/* check for errors */
	err = dlerror();
	if (err != NULL) {
		D_ERROR("failed to load %s: %s\n", modname, err);
		D_GOTO(err_lmod, rc = -DER_INVAL);
	}
	lmod->lm_dss_mod = smod;

	/* check module name is consistent */
	if (strcmp(smod->sm_name, modname) != 0) {
		D_ERROR("inconsistent module name %s != %s\n", modname,
			smod->sm_name);
		D_GOTO(err_hdl, rc = -DER_INVAL);
	}

	/* initialize the module */
	rc = smod->sm_init();
	if (rc) {
		D_ERROR("failed to init %s: %d\n", modname, rc);
		D_GOTO(err_hdl, rc = -DER_INVAL);
	}

	if (smod->sm_key != NULL)
		dss_register_key(smod->sm_key);

	/* register RPC handlers */
	rc = daos_rpc_register(smod->sm_proto_fmt, smod->sm_cli_count,
			       smod->sm_handlers, smod->sm_mod_id);
	if (rc) {
		D_ERROR("failed to register RPC for %s: %d\n",
			modname, rc);
		D_GOTO(err_mod_init, rc);
	}

	if (mod_facs != NULL)
		*mod_facs = smod->sm_facs;

	/* module successfully loaded, add it to the tracking list */
	D_MUTEX_LOCK(&loaded_mod_list_lock);
	d_list_add_tail(&lmod->lm_lk, &loaded_mod_list);
	D_MUTEX_UNLOCK(&loaded_mod_list_lock);
	return 0;

err_mod_init:
	dss_unregister_key(smod->sm_key);
	smod->sm_fini();
err_lmod:
	D_FREE(lmod);
err_hdl:
	dlclose(handle);
	return rc;
}

static int
dss_module_unload_internal(struct loaded_mod *lmod)
{
	struct dss_module	*smod = lmod->lm_dss_mod;
	int			 rc;

	/* unregister RPC handlers */
	rc = daos_rpc_unregister(smod->sm_proto_fmt);
	if (rc) {
		D_ERROR("failed to unregister RPC %d\n", rc);
		return rc;
	}

	dss_unregister_key(smod->sm_key);

	/* finalize the module */
	rc = smod->sm_fini();
	if (rc) {
		D_ERROR("module finalization failed for: %d\n", rc);
		return rc;

	}

	/* close the library handle */
	dlclose(lmod->lm_hdl);

	return rc;
}

int
dss_module_unload(const char *modname)
{
	struct loaded_mod	*lmod;

	/* lookup the module from the loaded module list */
	D_MUTEX_LOCK(&loaded_mod_list_lock);
	lmod = dss_module_search(modname);
	if (lmod == NULL) {
		D_MUTEX_UNLOCK(&loaded_mod_list_lock);
		/* module not found ... */
		return -DER_ENOENT;
	}
	d_list_del_init(&lmod->lm_lk);
	D_MUTEX_UNLOCK(&loaded_mod_list_lock);

	dss_module_unload_internal(lmod);

	/* free memory used to track this module instance */
	D_FREE(lmod);

	return 0;
}

int
dss_module_setup_all(void)
{
	struct loaded_mod      *mod;
	int			rc = 0;

	D_MUTEX_LOCK(&loaded_mod_list_lock);
	d_list_for_each_entry(mod, &loaded_mod_list, lm_lk) {
		struct dss_module *m = mod->lm_dss_mod;

		if (m->sm_setup == NULL)
			continue;
		rc = m->sm_setup();
		if (rc != 0) {
			D_ERROR("failed to set up module %s: %d\n", m->sm_name,
				rc);
			break;
		}
	}
	D_MUTEX_UNLOCK(&loaded_mod_list_lock);
	return rc;
}

int
dss_module_cleanup_all(void)
{
	struct loaded_mod      *mod;
	int			rc = 0;

	D_MUTEX_LOCK(&loaded_mod_list_lock);
	d_list_for_each_entry_reverse(mod, &loaded_mod_list, lm_lk) {
		struct dss_module *m = mod->lm_dss_mod;

		if (m->sm_cleanup == NULL)
			continue;
		rc = m->sm_cleanup();
		if (rc != 0) {
			D_ERROR("failed to clean up module %s: %d\n",
				m->sm_name, rc);
			break;
		}
	}
	D_MUTEX_UNLOCK(&loaded_mod_list_lock);
	return rc;
}

int
dss_module_init(void)
{
	return 0;
}

int
dss_module_fini(bool force)
{
	return 0;
}

void
dss_module_unload_all(void)
{
	struct loaded_mod	*mod;
	struct loaded_mod	*tmp;
	struct d_list_head	destroy_list;

	D_INIT_LIST_HEAD(&destroy_list);
	D_MUTEX_LOCK(&loaded_mod_list_lock);
	d_list_for_each_entry_safe(mod, tmp, &loaded_mod_list, lm_lk) {
		d_list_del_init(&mod->lm_lk);
		d_list_add(&mod->lm_lk, &destroy_list);
	}
	D_MUTEX_UNLOCK(&loaded_mod_list_lock);

	d_list_for_each_entry_safe(mod, tmp, &destroy_list, lm_lk) {
		d_list_del_init(&mod->lm_lk);
		dss_module_unload_internal(mod);
		D_FREE(mod);
	}
}
