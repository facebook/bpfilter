/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include <errno.h>

#include <bpfilter/chain.h>
#include <bpfilter/counter.h>
#include <bpfilter/front.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/io.h>
#include <bpfilter/list.h>
#include <bpfilter/logger.h>
#include <bpfilter/pack.h>
#include <bpfilter/request.h>
#include <bpfilter/response.h>

#include "bpfilter/set.h"
#include "cgen/cgen.h"
#include "cgen/handle.h"
#include "cgen/prog/link.h"
#include "cgen/prog/map.h"
#include "cgen/program.h"
#include "ctx.h"
#include "xlate/front.h"

static int _bf_cli_setup(void);
static int _bf_cli_teardown(void);
static int _bf_cli_request_handler(const struct bf_request *request,
                                   struct bf_response **response);
static int _bf_cli_pack(bf_wpack_t *pack);
static int _bf_cli_unpack(bf_rpack_node_t node);

const struct bf_front_ops cli_front = {
    .setup = _bf_cli_setup,
    .teardown = _bf_cli_teardown,
    .request_handler = _bf_cli_request_handler,
    .pack = _bf_cli_pack,
    .unpack = _bf_cli_unpack,
};

static int _bf_cli_setup(void)
{
    return 0;
}

static int _bf_cli_teardown(void)
{
    return 0;
}

int _bf_cli_ruleset_flush(const struct bf_request *request,
                          struct bf_response **response)
{
    (void)request;
    (void)response;

    bf_ctx_flush(BF_FRONT_CLI);

    return 0;
}

static int _bf_cli_ruleset_get(const struct bf_request *request,
                               struct bf_response **response)
{
    _clean_bf_list_ bf_list cgens = bf_list_default(NULL, NULL);
    _clean_bf_list_ bf_list chains = bf_list_default(NULL, bf_chain_pack);
    _clean_bf_list_ bf_list hookopts = bf_list_default(NULL, bf_hookopts_pack);
    _clean_bf_list_ bf_list counters =
        bf_list_default(bf_list_free, bf_list_pack);
    _free_bf_wpack_ bf_wpack_t *pack = NULL;
    int r;

    (void)request;

    r = bf_wpack_new(&pack);
    if (r)
        return r;

    r = bf_ctx_get_cgens_for_front(&cgens, BF_FRONT_CLI);
    if (r < 0)
        return bf_err_r(r, "failed to get cgen list");

    bf_list_foreach (&cgens, cgen_node) {
        struct bf_cgen *cgen = bf_list_node_get_data(cgen_node);
        _free_bf_list_ bf_list *cgen_counters = NULL;

        r = bf_list_add_tail(&chains, cgen->chain);
        if (r)
            return bf_err_r(r, "failed to add chain to list");

        r = bf_list_add_tail(&hookopts, cgen->handle->link ?
                                            cgen->handle->link->hookopts :
                                            NULL);
        if (r)
            return bf_err_r(r, "failed to add hookopts to list");

        r = bf_list_new(&cgen_counters,
                        &bf_list_ops_default(bf_counter_free, bf_counter_pack));
        if (r)
            return r;

        r = bf_cgen_get_counters(cgen, cgen_counters);
        if (r)
            return r;

        r = bf_list_add_tail(&counters, cgen_counters);
        if (r)
            return r;

        TAKE_PTR(cgen_counters);
    }

    bf_wpack_open_object(pack, "ruleset");
    bf_wpack_kv_list(pack, "chains", &chains);
    bf_wpack_kv_list(pack, "hookopts", &hookopts);
    bf_wpack_kv_list(pack, "counters", &counters);
    bf_wpack_close_object(pack);

    return bf_response_new_from_pack(response, pack);
}

int _bf_cli_ruleset_set(const struct bf_request *request,
                        struct bf_response **response)
{
    _clean_bf_list_ bf_list cgens = bf_list_default(NULL, NULL);
    _free_bf_rpack_ bf_rpack_t *pack;
    bf_rpack_node_t child, node;
    int r;

    assert(request);

    (void)response;

    bf_ctx_flush(BF_FRONT_CLI);

    r = bf_rpack_new(&pack, bf_request_data(request),
                     bf_request_data_len(request));
    if (r)
        return r;

    r = bf_rpack_kv_array(bf_rpack_root(pack), "ruleset", &child);
    if (r)
        return r;
    bf_rpack_array_foreach (child, node) {
        _free_bf_cgen_ struct bf_cgen *cgen = NULL;
        _free_bf_chain_ struct bf_chain *chain = NULL;
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        bf_rpack_node_t child;

        r = bf_rpack_kv_obj(node, "chain", &child);
        if (r)
            goto err_load;

        r = bf_chain_new_from_pack(&chain, child);
        if (r)
            goto err_load;

        r = bf_rpack_kv_node(node, "hookopts", &child);
        if (r)
            goto err_load;
        if (!bf_rpack_is_nil(child)) {
            r = bf_hookopts_new_from_pack(&hookopts, child);
            if (r)
                goto err_load;
        }

        r = bf_cgen_new(&cgen, BF_FRONT_CLI, &chain);
        if (r)
            goto err_load;

        r = bf_cgen_set(cgen, bf_request_ns(request),
                        hookopts ? &hookopts : NULL);
        if (r) {
            bf_err_r(r, "failed to set chain '%s'", cgen->chain->name);
            goto err_load;
        }

        r = bf_ctx_set_cgen(cgen);
        if (r) {
            /* The codegen is loaded already, if the daemon runs in persistent
             * mode, cleaning the codegen won't be sufficient to discard the
             * chain, it must be unpinned. */
            bf_cgen_unload(cgen);
            goto err_load;
        }

        TAKE_PTR(cgen);
    }

    return 0;

err_load:
    bf_ctx_flush(BF_FRONT_CLI);
    return r;
}

int _bf_cli_chain_set(const struct bf_request *request,
                      struct bf_response **response)
{
    struct bf_cgen *old_cgen;
    _free_bf_cgen_ struct bf_cgen *new_cgen = NULL;
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    _free_bf_rpack_ bf_rpack_t *pack = NULL;
    bf_rpack_node_t root, child;
    int r;

    assert(request);

    (void)response;

    r = bf_rpack_new(&pack, bf_request_data(request),
                     bf_request_data_len(request));
    if (r)
        return r;

    root = bf_rpack_root(pack);

    r = bf_rpack_kv_obj(root, "chain", &child);
    if (r)
        return r;
    r = bf_chain_new_from_pack(&chain, child);
    if (r)
        return r;

    r = bf_rpack_kv_node(root, "hookopts", &child);
    if (r)
        return r;
    if (!bf_rpack_is_nil(child)) {
        r = bf_hookopts_new_from_pack(&hookopts, child);
        if (r)
            return r;
    }

    r = bf_cgen_new(&new_cgen, BF_FRONT_CLI, &chain);
    if (r)
        return r;

    old_cgen = bf_ctx_get_cgen(new_cgen->chain->name);
    if (old_cgen) {
        /* bf_ctx_delete_cgen() can only fail if the codegen is not found,
         * but we know this codegen exist. */
        (void)bf_ctx_delete_cgen(old_cgen, true);
    }

    r = bf_cgen_set(new_cgen, bf_request_ns(request),
                    hookopts ? &hookopts : NULL);
    if (r)
        return r;

    r = bf_ctx_set_cgen(new_cgen);
    if (r) {
        bf_cgen_unload(new_cgen);
        return r;
    }

    TAKE_PTR(new_cgen);

    return r;
}

static int _bf_cli_chain_get(const struct bf_request *request,
                             struct bf_response **response)
{
    _clean_bf_list_ bf_list counters =
        bf_list_default(bf_counter_free, bf_counter_pack);
    struct bf_cgen *cgen;
    _cleanup_free_ char *name = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    int r;

    r = bf_rpack_new(&rpack, bf_request_data(request),
                     bf_request_data_len(request));
    if (r)
        return r;

    r = bf_rpack_kv_str(bf_rpack_root(rpack), "name", &name);
    if (r)
        return r;

    cgen = bf_ctx_get_cgen(name);
    if (!cgen)
        return bf_err_r(-ENOENT, "chain '%s' not found", name);

    r = bf_cgen_get_counters(cgen, &counters);
    if (r)
        return bf_err_r(r, "failed to request counters for '%s'", name);

    r = bf_wpack_new(&wpack);
    if (r)
        return r;

    bf_wpack_open_object(wpack, "chain");
    r = bf_chain_pack(cgen->chain, wpack);
    if (r)
        return r;
    bf_wpack_close_object(wpack);

    if (cgen->handle->link) {
        bf_wpack_open_object(wpack, "hookopts");
        r = bf_hookopts_pack(cgen->handle->link->hookopts, wpack);
        if (r)
            return r;
        bf_wpack_close_object(wpack);
    } else {
        bf_wpack_kv_nil(wpack, "hookopts");
    }

    bf_wpack_kv_list(wpack, "counters", &counters);

    return bf_response_new_from_pack(response, wpack);
}

int _bf_cli_chain_prog_fd(const struct bf_request *request,
                          struct bf_response **response)
{
    struct bf_cgen *cgen;
    _free_bf_rpack_ bf_rpack_t *pack = NULL;
    _cleanup_free_ char *name = NULL;
    int r;

    (void)response;

    r = bf_rpack_new(&pack, bf_request_data(request),
                     bf_request_data_len(request));
    if (r)
        return r;

    r = bf_rpack_kv_str(bf_rpack_root(pack), "name", &name);
    if (r)
        return r;

    cgen = bf_ctx_get_cgen(name);
    if (!cgen)
        return bf_err_r(-ENOENT, "failed to find chain '%s'", name);

    if (cgen->handle->prog_fd == -1)
        return bf_err_r(-ENODEV, "chain '%s' has no loaded program", name);

    r = bf_send_fd(bf_request_fd(request), cgen->handle->prog_fd);
    if (r < 0)
        return bf_err_r(errno, "failed to send prog FD for '%s'", name);

    return 0;
}

int _bf_cli_chain_logs_fd(const struct bf_request *request,
                          struct bf_response **response)
{
    struct bf_cgen *cgen;
    _free_bf_rpack_ bf_rpack_t *pack = NULL;
    _cleanup_free_ char *name = NULL;
    int r;

    (void)response;

    r = bf_rpack_new(&pack, bf_request_data(request),
                     bf_request_data_len(request));
    if (r)
        return r;

    r = bf_rpack_kv_str(bf_rpack_root(pack), "name", &name);
    if (r)
        return r;

    cgen = bf_ctx_get_cgen(name);
    if (!cgen)
        return bf_err_r(-ENOENT, "failed to find chain '%s'", name);

    if (!cgen->handle->lmap)
        return bf_err_r(-ENOENT, "chain '%s' has no logs buffer", name);

    r = bf_send_fd(bf_request_fd(request), cgen->handle->lmap->fd);
    if (r < 0)
        return bf_err_r(errno, "failed to send logs FD for '%s'", name);

    return 0;
}

int _bf_cli_chain_load(const struct bf_request *request,
                       struct bf_response **response)
{
    _free_bf_cgen_ struct bf_cgen *cgen = NULL;
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_rpack_ bf_rpack_t *pack = NULL;
    bf_rpack_node_t child;
    int r;

    assert(request);

    (void)response;

    r = bf_rpack_new(&pack, bf_request_data(request),
                     bf_request_data_len(request));
    if (r)
        return r;

    r = bf_rpack_kv_obj(bf_rpack_root(pack), "chain", &child);
    if (r)
        return r;
    r = bf_chain_new_from_pack(&chain, child);
    if (r)
        return r;

    if (bf_ctx_get_cgen(chain->name)) {
        return bf_err_r(-EEXIST,
                        "_bf_cli_chain_load: chain '%s' already exists",
                        chain->name);
    }

    r = bf_cgen_new(&cgen, BF_FRONT_CLI, &chain);
    if (r)
        return r;

    r = bf_cgen_load(cgen);
    if (r)
        return r;

    r = bf_ctx_set_cgen(cgen);
    if (r) {
        bf_cgen_unload(cgen);
        return bf_err_r(
            r, "bf_ctx_set_cgen: failed to add cgen to the runtime context");
    }

    TAKE_PTR(cgen);

    return r;
}

int _bf_cli_chain_attach(const struct bf_request *request,
                         struct bf_response **response)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    _free_bf_rpack_ bf_rpack_t *pack = NULL;
    _cleanup_free_ char *name = NULL;
    struct bf_cgen *cgen = NULL;
    bf_rpack_node_t child;
    int r;

    assert(request);

    (void)response;

    r = bf_rpack_new(&pack, bf_request_data(request),
                     bf_request_data_len(request));
    if (r)
        return r;

    r = bf_rpack_kv_str(bf_rpack_root(pack), "name", &name);
    if (r)
        return r;

    r = bf_rpack_kv_obj(bf_rpack_root(pack), "hookopts", &child);
    if (r)
        return r;
    r = bf_hookopts_new_from_pack(&hookopts, child);
    if (r)
        return r;

    cgen = bf_ctx_get_cgen(name);
    if (!cgen)
        return bf_err_r(-ENOENT, "chain '%s' does not exist", name);
    if (cgen->handle->link)
        return bf_err_r(-EBUSY, "chain '%s' is already linked to a hook", name);

    r = bf_hookopts_validate(hookopts, cgen->chain->hook);
    if (r)
        return bf_err_r(r, "failed to validate hook options");

    r = bf_cgen_attach(cgen, bf_request_ns(request), &hookopts);
    if (r)
        return bf_err_r(r, "failed to attach codegen to hook");

    return r;
}

int _bf_cli_chain_update(const struct bf_request *request,
                         struct bf_response **response)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    struct bf_cgen *cgen = NULL;
    _free_bf_rpack_ bf_rpack_t *pack = NULL;
    bf_rpack_node_t child;
    int r;

    assert(request);

    (void)response;

    r = bf_rpack_new(&pack, bf_request_data(request),
                     bf_request_data_len(request));
    if (r)
        return r;

    r = bf_rpack_kv_obj(bf_rpack_root(pack), "chain", &child);
    if (r)
        return r;
    r = bf_chain_new_from_pack(&chain, child);
    if (r)
        return r;

    cgen = bf_ctx_get_cgen(chain->name);
    if (!cgen)
        return -ENOENT;

    r = bf_cgen_update(cgen, &chain, 0);
    if (r)
        return -EINVAL;

    return r;
}

int _bf_cli_chain_flush(const struct bf_request *request,
                        struct bf_response **response)
{
    struct bf_cgen *cgen = NULL;
    _free_bf_rpack_ bf_rpack_t *pack = NULL;
    _cleanup_free_ char *name = NULL;
    int r;

    assert(request);

    (void)response;

    r = bf_rpack_new(&pack, bf_request_data(request),
                     bf_request_data_len(request));
    if (r)
        return r;

    r = bf_rpack_kv_str(bf_rpack_root(pack), "name", &name);
    if (r)
        return r;

    cgen = bf_ctx_get_cgen(name);
    if (!cgen)
        return -ENOENT;

    return bf_ctx_delete_cgen(cgen, true);
}

int _bf_cli_chain_update_set(const struct bf_request *request,
                             struct bf_response **response)
{
    _free_bf_set_ struct bf_set *to_add = NULL;
    _free_bf_set_ struct bf_set *to_remove = NULL;
    _free_bf_chain_ struct bf_chain *new_chain = NULL;
    _free_bf_rpack_ bf_rpack_t *pack = NULL;
    struct bf_set *dest_set = NULL;
    _cleanup_free_ char *chain_name = NULL;
    struct bf_cgen *cgen = NULL;
    bf_rpack_node_t child;
    int r;

    assert(request);

    (void)response;

    r = bf_rpack_new(&pack, bf_request_data(request),
                     bf_request_data_len(request));
    if (r)
        return r;

    r = bf_rpack_kv_str(bf_rpack_root(pack), "name", &chain_name);
    if (r)
        return r;

    r = bf_rpack_kv_obj(bf_rpack_root(pack), "to_add", &child);
    if (r)
        return r;
    r = bf_set_new_from_pack(&to_add, child);
    if (r)
        return r;

    r = bf_rpack_kv_obj(bf_rpack_root(pack), "to_remove", &child);
    if (r)
        return r;
    r = bf_set_new_from_pack(&to_remove, child);
    if (r)
        return r;

    if (!bf_streq(to_add->name, to_remove->name))
        return bf_err_r(-EINVAL, "to_add->name must match to_remove->name");

    cgen = bf_ctx_get_cgen(chain_name);
    if (!cgen)
        return bf_err_r(-ENOENT, "chain '%s' does not exist", chain_name);

    r = bf_chain_new_from_copy(&new_chain, cgen->chain);
    if (r)
        return r;

    dest_set = bf_chain_get_set_by_name(new_chain, to_add->name);
    if (!dest_set)
        return bf_err_r(-ENOENT, "set '%s' does not exist", to_add->name);

    r = bf_set_add_many(dest_set, &to_add);
    if (r)
        return bf_err_r(r, "failed to calculate set union");

    r = bf_set_remove_many(dest_set, &to_remove);
    if (r)
        return bf_err_r(r, "failed to calculate set difference");

    r = bf_cgen_update(cgen, &new_chain,
                       BF_FLAG(BF_CGEN_UPDATE_PRESERVE_COUNTERS));
    if (r)
        return bf_err_r(r, "failed to update chain with new set data");

    return 0;
}

static int _bf_cli_request_handler(const struct bf_request *request,
                                   struct bf_response **response)
{
    int r;

    assert(request);
    assert(response);

    switch (bf_request_cmd(request)) {
    case BF_REQ_RULESET_FLUSH:
        r = _bf_cli_ruleset_flush(request, response);
        break;
    case BF_REQ_RULESET_SET:
        r = _bf_cli_ruleset_set(request, response);
        break;
    case BF_REQ_RULESET_GET:
        r = _bf_cli_ruleset_get(request, response);
        break;
    case BF_REQ_CHAIN_SET:
        r = _bf_cli_chain_set(request, response);
        break;
    case BF_REQ_CHAIN_GET:
        r = _bf_cli_chain_get(request, response);
        break;
    case BF_REQ_CHAIN_PROG_FD:
        r = _bf_cli_chain_prog_fd(request, response);
        break;
    case BF_REQ_CHAIN_LOGS_FD:
        r = _bf_cli_chain_logs_fd(request, response);
        break;
    case BF_REQ_CHAIN_LOAD:
        r = _bf_cli_chain_load(request, response);
        break;
    case BF_REQ_CHAIN_ATTACH:
        r = _bf_cli_chain_attach(request, response);
        break;
    case BF_REQ_CHAIN_UPDATE:
        r = _bf_cli_chain_update(request, response);
        break;
    case BF_REQ_CHAIN_FLUSH:
        r = _bf_cli_chain_flush(request, response);
        break;
    case BF_REQ_CHAIN_UPDATE_SET:
        r = _bf_cli_chain_update_set(request, response);
        break;
    default:
        r = bf_err_r(-EINVAL, "unsupported command %d for CLI front-end",
                     bf_request_cmd(request));
        break;
    }

    /* If the callback don't need to send data back to the client, it can skip
     * the response creation and return a status code instead (0 on success,
     * negative errno value on error). The response is created based on the
     * status code. */
    if (!*response) {
        if (!r)
            r = bf_response_new_success(response, NULL, 0);
        else
            r = bf_response_new_failure(response, r);
    }

    return r;
}

static int _bf_cli_pack(bf_wpack_t *pack)
{
    (void)pack;

    return 0;
}

static int _bf_cli_unpack(bf_rpack_node_t node)
{
    (void)node;

    return 0;
}
