/*
 * Copyright 2015 Maas-Maarten Zeeman
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/*
 * ecrypt -- an erlang openssl evp nif.
*/

#include <erl_nif.h>
#include <string.h>
#include <stdio.h>

#include <openssl/evp.h>

/* This shall correspond to the similar macro in crypto.erl */
/* Current value is: erlang:system_info(context_reductions) * 10 */
#define MAX_BYTES_TO_NIF 20000

#define CONSUME_REDS(NifEnv, Ibin)                      \
do {                                                    \
    int _cost = ((Ibin).size  * 100) / MAX_BYTES_TO_NIF;\
    if (_cost) {                                        \
        (void) enif_consume_timeslice((NifEnv),         \
                  (_cost > 100) ? 100 : _cost);         \
    }                                                   \
} while (0)

static ErlNifResourceType *evp_cipher_ctx_type = NULL;

/* atoms */
static ERL_NIF_TERM atom_true;
static ERL_NIF_TERM atom_false;
static ERL_NIF_TERM atom_encrypt;
static ERL_NIF_TERM atom_decrypt;
static ERL_NIF_TERM atom_ok;
static ERL_NIF_TERM atom_error;

static ERL_NIF_TERM
make_atom(ErlNifEnv *env, const char *atom_name)
{
    ERL_NIF_TERM atom;

    if(enif_make_existing_atom(env, atom_name, &atom, ERL_NIF_LATIN1))
        return atom;

    return enif_make_atom(env, atom_name);
}

static ERL_NIF_TERM
make_ok_tuple(ErlNifEnv *env, ERL_NIF_TERM value)
{
    return enif_make_tuple2(env, atom_ok, value);
}

static ERL_NIF_TERM
make_error_tuple(ErlNifEnv *env, const char *reason)
{
    return enif_make_tuple2(env, atom_error, make_atom(env, reason));
}

static void
destruct_evp_cipher_ctx(ErlNifEnv *env, void *arg) {
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *) arg;
    if(EVP_CIPHER_CTX_cleanup(ctx) != 1) {

    }
};

/*
 * Create a new cipher ctx
 */
static ERL_NIF_TERM
ecrypt_new_cipher_ctx(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    EVP_CIPHER_CTX *new;
    ERL_NIF_TERM ctx;

    new = enif_alloc_resource(evp_cipher_ctx_type, sizeof(EVP_CIPHER_CTX));
    if(!new)
        return make_error_tuple(env, "no_memory");

    EVP_CIPHER_CTX_init(new);

    ctx = enif_make_resource(env, new);
    enif_release_resource(new);

    return make_ok_tuple(env, ctx);
}

static ERL_NIF_TERM
ecrypt_cleanup_cipher_ctx(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    EVP_CIPHER_CTX *ctx;

    if(argc != 1)
        return enif_make_badarg(env);

    if(!enif_get_resource(env, argv[0], evp_cipher_ctx_type, (void **) &ctx))
        return enif_make_badarg(env);

    if(EVP_CIPHER_CTX_cleanup(ctx) != 1) {
        return atom_error;
    }

    return atom_ok;
}

static ERL_NIF_TERM
ecrypt_nid(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    EVP_CIPHER_CTX *ctx;
    int nid;
    
    if(argc != 1)
        return enif_make_badarg(env);

    if(!enif_get_resource(env, argv[0], evp_cipher_ctx_type, (void **) &ctx))
        return enif_make_badarg(env);

    if(!ctx->cipher)
        return enif_make_badarg(env);

    nid = EVP_CIPHER_CTX_nid(ctx);
    return enif_make_int(env, nid);
}

static ERL_NIF_TERM
ecrypt_block_size(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    EVP_CIPHER_CTX *ctx;
    
    if(argc != 1)
        return enif_make_badarg(env);

    if(!enif_get_resource(env, argv[0], evp_cipher_ctx_type, (void **) &ctx))
        return enif_make_badarg(env);

    if(!ctx->cipher)
        return enif_make_badarg(env);

    return enif_make_int(env, EVP_CIPHER_CTX_block_size(ctx));
}

static ERL_NIF_TERM
ecrypt_iv_length(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    EVP_CIPHER_CTX *ctx;
    
    if(argc != 1)
        return enif_make_badarg(env);

    if(!enif_get_resource(env, argv[0], evp_cipher_ctx_type, (void **) &ctx))
        return enif_make_badarg(env);

    if(!ctx->cipher)
        return enif_make_badarg(env);

    return enif_make_int(env, EVP_CIPHER_CTX_iv_length(ctx));
}

static ERL_NIF_TERM
ecrypt_key_length(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    EVP_CIPHER_CTX *ctx;
    
    if(argc != 1)
        return enif_make_badarg(env);

    if(!enif_get_resource(env, argv[0], evp_cipher_ctx_type, (void **) &ctx))
        return enif_make_badarg(env);

    if(!ctx->cipher)
        return enif_make_badarg(env);

    return enif_make_int(env, EVP_CIPHER_CTX_key_length(ctx));
}

static ERL_NIF_TERM
ecrypt_cipher_ctx_cleanup(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    EVP_CIPHER_CTX *ctx;
    
    if(argc != 1)
        return enif_make_badarg(env);

    if(!enif_get_resource(env, argv[0], evp_cipher_ctx_type, (void **) &ctx))
        return enif_make_badarg(env);

    if(EVP_CIPHER_CTX_cleanup(ctx) != 1) {
        make_error_tuple(env, "cleanup_error");
    }

    return atom_ok;
}

static ERL_NIF_TERM
ecrypt_cipher_init2(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    EVP_CIPHER_CTX *ctx;
    ErlNifBinary bin;
    ERL_NIF_TERM eos = enif_make_int(env, 0);
    EVP_CIPHER *cipher; 

    if(argc != 2)
        return enif_make_badarg(env);

    if(!enif_get_resource(env, argv[0], evp_cipher_ctx_type, (void **) &ctx))
        return enif_make_badarg(env);

    if(!enif_inspect_iolist_as_binary(env, enif_make_list2(env, argv[1], eos), &bin))
        return enif_make_badarg(env);

    cipher = EVP_get_cipherbyname((char*) bin.data);
    if(!cipher)
        return make_error_tuple(env, "unknown_cipher");

    EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, -1);

    return atom_ok;
}

static ERL_NIF_TERM
ecrypt_cipher_init6(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    EVP_CIPHER_CTX *ctx;
    ErlNifBinary alg;
    ErlNifBinary key;
    ErlNifBinary iv;
    ERL_NIF_TERM eos = enif_make_int(env, 0);
    EVP_CIPHER *cipher; 
    int enc, pad;

    if(argc != 6)
        return enif_make_badarg(env);

    /* Ctx */
    if(!enif_get_resource(env, argv[0], evp_cipher_ctx_type, (void **) &ctx))
        return enif_make_badarg(env);

    /* Alg */
    if(!enif_inspect_iolist_as_binary(env, enif_make_list2(env, argv[1], eos), &alg))
        return enif_make_badarg(env);

    /* Key */
    if(!enif_inspect_iolist_as_binary(env, argv[2], &key))
        return enif_make_badarg(env);

    /* IV */
    if(!enif_inspect_iolist_as_binary(env, argv[3], &iv))
        return enif_make_badarg(env);

    /* Mode */
    if(enif_is_identical(atom_encrypt, argv[4])) {
        enc = 1;
    } else if(enif_is_identical(atom_decrypt, argv[4])) {
        enc = 0;
    } else {
        return enif_make_badarg(env);
    }

    /* Padding */
    if(enif_is_identical(atom_true, argv[5])) {
        pad = 1;
    } else if(enif_is_identical(atom_false, argv[5])) {
        pad = 0;
    } else {
        return enif_make_badarg(env);
    }

    cipher = EVP_get_cipherbyname((char*) alg.data);
    if(!cipher)
        return make_error_tuple(env, "unknown_cipher");

    if(EVP_CIPHER_key_length(cipher) != key.size)
        return make_error_tuple(env, "key_length");

    if(EVP_CIPHER_iv_length(cipher) != iv.size)
        return make_error_tuple(env, "iv_length");

    if(0 == EVP_CipherInit(ctx, cipher, key.data, iv.data, enc))
        return make_error_tuple(env, "init");

    if(0 == EVP_CIPHER_CTX_set_padding(ctx, pad))
        return make_error_tuple(env, "padding");

    return atom_ok;
}

static ERL_NIF_TERM
ecrypt_cipher_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    EVP_CIPHER_CTX *ctx;
    ErlNifBinary data;
    int outl;
    unsigned char * buf;
    ERL_NIF_TERM bin_buf;

    if(argc != 2)
        return enif_make_badarg(env);

    if(!enif_get_resource(env, argv[0], evp_cipher_ctx_type, (void **) &ctx))
        return enif_make_badarg(env);

    if(!enif_inspect_iolist_as_binary(env, argv[1], &data))
        return enif_make_badarg(env);

    outl = EVP_CIPHER_CTX_block_size(ctx) + data.size - 1;
    if(0 == EVP_CipherUpdate(ctx, enif_make_new_binary(env, outl, &bin_buf), 
            &outl, data.data, data.size)) {
        return enif_make_badarg(env);
    }

    CONSUME_REDS(env, data);

    return enif_make_sub_binary(env, bin_buf, 0, outl);
}

static ERL_NIF_TERM
ecrypt_cipher_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    EVP_CIPHER_CTX *ctx;
    ERL_NIF_TERM bin_buf;
    int outl;

    if(argc != 1)
        return enif_make_badarg(env);

    if(!enif_get_resource(env, argv[0], evp_cipher_ctx_type, (void **) &ctx))
        return enif_make_badarg(env);

    if(0 == EVP_CipherFinal(ctx, 
            enif_make_new_binary(env, EVP_CIPHER_CTX_block_size(ctx), &bin_buf), &outl)) {
        return enif_make_badarg(env);
    }

    return enif_make_sub_binary(env, bin_buf, 0, outl);
}


/*
 * Load the nif. Initialize some stuff and such
 */
static int 
on_load(ErlNifEnv* env, void** priv, ERL_NIF_TERM info)
{
    ErlNifResourceType *rt;

    rt = enif_open_resource_type(env, "ecrypt", "evp_cipher_ctx",
            destruct_evp_cipher_ctx, ERL_NIF_RT_CREATE, NULL);
    if(!rt) 
        return -1;

    evp_cipher_ctx_type = rt;

    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();
    OpenSSL_add_all_ciphers();

    atom_true = enif_make_atom(env, "true");
    atom_false = enif_make_atom(env, "false");
    atom_encrypt = enif_make_atom(env, "encrypt");
    atom_decrypt = enif_make_atom(env, "decrypt");
    atom_ok = enif_make_atom(env, "ok");
    atom_error = enif_make_atom(env, "error");

    return 0;
}

static int on_reload(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info)
{
    return 0;
}

static int on_upgrade(ErlNifEnv* env, void** priv, void** old_priv_data, ERL_NIF_TERM load_info)
{
    return 0;
}

static ErlNifFunc nif_funcs[] = {
    {"new_cipher_ctx", 0, ecrypt_new_cipher_ctx},
    {"cleanup_cipher_ctx", 1, ecrypt_cleanup_cipher_ctx},

    {"cipher_init", 2, ecrypt_cipher_init2},
    {"cipher_init", 6, ecrypt_cipher_init6},
    {"cipher_update", 2, ecrypt_cipher_update},
    {"cipher_final", 1, ecrypt_cipher_final},

    {"nid", 1, ecrypt_nid},
    {"block_size", 1, ecrypt_block_size},
    {"key_length", 1, ecrypt_key_length},
    {"iv_length", 1, ecrypt_iv_length}
};

ERL_NIF_INIT(ecrypt_nif, nif_funcs, on_load, on_reload, on_upgrade, NULL);
