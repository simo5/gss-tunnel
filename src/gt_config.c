/* Copyright (C) 2015 Gsstunnel Contributors, for licensee see COPYING */

#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "gsstunnel.h"

static int init_config(const char *cfg_file, struct ini_cfgobj **ini_config)
{
    struct ini_cfgfile *file_ctx = NULL;
    int ret;

    *ini_config = NULL;

    ret = ini_config_create(ini_config);
    if (ret) {
        ret = ERR_UNKNOWN;
        goto cleanup;
    }

    ret = ini_config_file_open(cfg_file, 0, &file_ctx);
    if (ret) {
        ret = ERR_BADCONF;
        goto cleanup;
    }

    ret = ini_config_parse(file_ctx, INI_STOP_ON_ANY,
                           INI_MS_MERGE | INI_MV1S_ALLOW | INI_MV2S_ALLOW,
                           INI_PARSE_NOWRAP, *ini_config);
    if (ret) {
        char **errors = NULL;
        if (ini_config_error_count(*ini_config)) {
            ini_config_get_errors(*ini_config, &errors);
            if (errors) {
                ini_config_print_errors(stderr, errors);
                ini_config_free_errors(errors);
            }
        }
        ret = ERR_BADCONF;
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (ret) {
        ini_config_destroy(*ini_config);
        *ini_config = NULL;
    }
    ini_config_file_destroy(file_ctx);
    return ret;
}

static int get_string(struct ini_cfgobj *ini_config,
                      const char *section,
                      const char *key,
                      const char *defval,
                      char **value)
{
    struct value_obj *value_obj;
    const char *val;
    int ret;

    if (!value) return EINVAL;

    ret = ini_get_config_valueobj(section, key, ini_config,
                                  INI_GET_FIRST_VALUE, &value_obj);
    if (ret) return ret;
    if (!value_obj) {
        if (!defval) return ENOENT;
        else {
            *value = strdup(defval);
            if (!*value) return ENOENT;
            return 0;
        }
    }

    val = ini_get_const_string_config_value(value_obj, &ret);
    if (ret) return ret;

    *value = strdup(val);
    if (!*value) return ENOENT;
    return 0;
}

static int get_sections(struct ini_cfgobj *ini_config, char ***list, int *count)
{
    int ret;
    *list = ini_get_section_list(ini_config, count, &ret);
    return ret;
}

static void free_sections(char ***sections)
{
    ini_free_section_list(*sections);
    *sections = NULL;
}

struct auto_config {
    struct gt_config *cfg;
    int ret;
};

static void load_config_cleanup(struct auto_config *ac)
{
    if (ac->ret) {
        if (ac->cfg->svcs) {
            /* TODO: free svcs */
        }
        if (ac->cfg->ini_config) {
            ini_config_destroy(ac->cfg->ini_config);
        }
    }
}

int load_config(const char *cfg_file, struct gt_config *cfg)
{
    AUTOCLEAN(struct auto_config ac, load_config_cleanup) = { cfg, 0 };
    AUTOCLEAN(char **sections, free_sections) = NULL;
    char *value;
    int seccount = 0;
    int i;

    ac.ret = init_config(cfg_file, &cfg->ini_config);
    if (ac.ret) return ac.ret;

    ac.ret = get_sections(cfg->ini_config, &sections, &seccount);
    if (ac.ret) return ac.ret;

    cfg->svcs = calloc(seccount, sizeof(struct gt_service));
    if (!cfg->svcs) {
        ac.ret = ENOMEM;
        return ac.ret;
    }
    cfg->num_svcs = seccount;

    for (i = 0; i < seccount; i++) {
        cfg->svcs[i].name = strdup(sections[i]);
        if (!cfg->svcs[i].name) return ENOMEM;

        value = NULL;
        ac.ret = get_string(cfg->ini_config, cfg->svcs[i].name,
                         "client", "no", &value);
        if (ac.ret) return ac.ret;
        if (strcmp(value, "yes") == 0) {
            cfg->svcs[i].client = true;
        }
        free(value);

        ac.ret = get_string(cfg->ini_config, cfg->svcs[i].name,
                         "target name", NULL, &cfg->svcs[i].target_name);
        if (ac.ret && ac.ret != ENOENT) return ac.ret;

        ac.ret = get_string(cfg->ini_config, cfg->svcs[i].name,
                         "accept", NULL, &cfg->svcs[i].accept);
        if (ac.ret && ac.ret != ENOENT) return ac.ret;

        ac.ret = get_string(cfg->ini_config, cfg->svcs[i].name,
                         "connect", NULL, &cfg->svcs[i].connect);
        if (ac.ret && ac.ret != ENOENT) return ac.ret;

        ac.ret = get_string(cfg->ini_config, cfg->svcs[i].name,
                         "exec", NULL, &cfg->svcs[i].exec);
        if (ac.ret && ac.ret != ENOENT) return ac.ret;

        /* TODO: mechs */
        /* TODO: cred_store */
    }
    ac.ret = 0;

    return ac.ret;
}

