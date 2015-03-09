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
    cipher_init/2,
    block_size/1,
    key_length/1,
    iv_length/1,
    cipher_ctx_cleanup/1,
    nid/1
]).

-on_load(init/0).

new_cipher_ctx() ->
    exit(nif_library_not_loaded).

cipher_init(_Ctx, _Name) ->
    exit(nif_library_not_loaded).

block_size(_Ctx) ->
    exit(nif_library_not_loaded).

key_length(_Ctx) ->
    exit(nif_library_not_loaded).

iv_length(_Ctx) ->
    exit(nif_library_not_loaded).

cipher_ctx_cleanup(_Ctx) ->
    exit(nif_library_not_loaded).

nid(_Ctx) ->
    exit(nif_library_not_loaded).

init() ->
    NifName = "ecrypt_nif",
    NifFileName = case code:priv_dir(ecrypt) of
                      {error, bad_name} -> filename:join("priv", NifName);
                      Dir -> filename:join(Dir, NifName)
                  end,
    ok = erlang:load_nif(NifFileName, 0).

