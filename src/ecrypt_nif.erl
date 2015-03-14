%% @author Maas-Maarten Zeeman <mmzeeman@xs4all.nl>
%% @copyright 2015 Maas-Maarten Zeeman

%% @doc Low level erlang interface to evp ciphers in openssl

%% Copyright 2015 Maas-Maarten Zeeman
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%% 
%%     http://www.apache.org/licenses/LICENSE-2.0
%% 
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(ecrypt_nif).
-author("Maas-Maarten Zeeman <mmzeeman@xs4all.nl>").

-export([
    new_cipher_ctx/0,
    cleanup_cipher_ctx/1,

    block_size/1,
    key_length/1,
    iv_length/1,
    nid/1,

    cipher_info/1,

    cipher_init/2,
    cipher_init/5,
    cipher_update/2,
    cipher_final/1
]).

-on_load(init/0).

cipher_info(Name) when is_binary(Name) orelse is_list(Name) ->
    {ok, Ctx} = new_cipher_ctx(),
    cipher_init(Ctx, Name),
    Info = cipher_info_ctx(Ctx),
    cleanup_cipher_ctx(Ctx),
    Info.

cipher_info_ctx(Ctx) ->
    [{block_size, block_size(Ctx)},
        {key_length, key_length(Ctx)},
        {iv_length, iv_length(Ctx)}].

block_size(_Ctx) ->
    exit(nif_library_not_loaded).

key_length(_Ctx) ->
    exit(nif_library_not_loaded).

iv_length(_Ctx) ->
    exit(nif_library_not_loaded).

nid(_Ctx) ->
    exit(nif_library_not_loaded).

new_cipher_ctx() ->
    exit(nif_library_not_loaded).

cleanup_cipher_ctx(_Ctx) ->
    exit(nif_library_not_loaded).

cipher_init(_Ctx, _Alg) ->
    exit(nif_library_not_loaded).

cipher_init(_Ctx, _Alg, _Key, _Iv, _Encrypt) ->
    exit(nif_library_not_loaded).

cipher_update(_Ctx, _Data) ->
    exit(nif_library_not_loaded).

cipher_final(_Ctx) ->
    exit(nif_library_not_loaded).

init() ->
    NifName = "ecrypt_nif",
    NifFileName = case code:priv_dir(ecrypt) of
                      {error, bad_name} -> filename:join("priv", NifName);
                      Dir -> filename:join(Dir, NifName)
                  end,
    ok = erlang:load_nif(NifFileName, 0).



