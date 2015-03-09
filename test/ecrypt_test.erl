%%
%%
%%

-module(ecrypt_test).

-include_lib("eunit/include/eunit.hrl").

new_cipher_ctx_test() ->
    {ok, _Ctx} = ecrypt_nif:new_cipher_ctx(),
    ok.

empty_ctx_test() ->
    {ok, Ctx} = ecrypt_nif:new_cipher_ctx(),

    ?assertError(badarg, ecrypt_nif:nid(Ctx)),
    ?assertError(badarg, ecrypt_nif:key_length(Ctx)),
    ?assertError(badarg, ecrypt_nif:iv_length(Ctx)),
    ?assertError(badarg, ecrypt_nif:block_size(Ctx)),

    ok.


cipher_init_test() ->
    {ok, Ctx} = ecrypt_nif:new_cipher_ctx(),
    ok = ecrypt_nif:cipher_init(Ctx, <<"aes-128-cfb">>),

    ?assertEqual(421, ecrypt_nif:nid(Ctx)),
    ?assertEqual(16, ecrypt_nif:key_length(Ctx)),
    ?assertEqual(16, ecrypt_nif:iv_length(Ctx)),
    ?assertEqual(1, ecrypt_nif:block_size(Ctx)),

    ok.


cleanup_test() ->
    {ok, Ctx} = ecrypt_nif:new_cipher_ctx(),
    ok = ecrypt_nif:cipher_ctx_cleanup(Ctx),
    ok.

module_info_test() ->
    ecrypt_nif:module_info(),

    ok.

