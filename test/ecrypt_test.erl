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

encrypt_test() ->
    {ok, Ctx} = ecrypt_nif:new_cipher_ctx(),

    ?assertEqual([{block_size, 16}, 
            {key_length, 24}, 
            {iv_length, 16}], ecrypt_nif:cipher_info(<<"aes-192-cbc">>)),

    ok = ecrypt_nif:cipher_init(Ctx, <<"aes-192-cbc">>, 
        <<"012345670123456701234567">>, <<"0123456701234567">>, encrypt),

    ?assertEqual(ok, ecrypt_nif:cipher_update(Ctx, <<"012345678012345678">>)),
    
    ecrypt_nif:cipher_update(Ctx, <<"012345678">>),
    ecrypt_nif:cipher_update(Ctx, <<"0123">>),
    ecrypt_nif:cipher_update(Ctx, <<"0123">>),
    ecrypt_nif:cipher_update(Ctx, <<"0123">>),
    ecrypt_nif:cipher_update(Ctx, <<"0123">>),
    ecrypt_nif:cipher_update(Ctx, <<"0123">>),
    ecrypt_nif:cipher_update(Ctx, <<"0123">>),
    ecrypt_nif:cipher_update(Ctx, <<"0123">>),
    ecrypt_nif:cipher_update(Ctx, <<"0123">>),
    ecrypt_nif:cipher_update(Ctx, <<"0123aksdjfkasjdfkjasdkfjkasdjfkasdfjaskdfjksajfksajdfkjaskdfjkasjfkasjdfkjaskdfjkasdjfkasfkajskfjaskjfkasdjf">>),
    ecrypt_nif:cipher_final(Ctx),

    ok.


speed_test() ->
    {ok, Ctx} = ecrypt_nif:new_cipher_ctx(),

    ok = ecrypt_nif:cipher_init(Ctx, <<"aes-128-cbc">>, 
        <<"0123456701234567">>, <<"0123456701234567">>, encrypt),

    Mb = crypto:rand_bytes(50*1024*1024),
    T1 = os:timestamp(),
    %% EncData = encrypt_new(Ctx, Mb),
    EncData = ecrypt_nif:cipher_update(Ctx, Mb),
    Final = ecrypt_nif:cipher_final(Ctx),
    T2 = os:timestamp(),

    io:fwrite(standard_error, "Encrypted: ~p, Time: ~.2fms~n", [erlang:byte_size(EncData), 
            timer:now_diff(T2, T1)/1000.0]),

    ok.

old_speed_test() ->
    Mb = crypto:rand_bytes(50*1024*1024),

    T1 = os:timestamp(),
    EncData = crypto:block_encrypt(aes_cbc128, <<"0123456701234567">>, <<"0123456701234567">>, Mb),
    T2 = os:timestamp(),

    io:fwrite(standard_error, "Old Encrypted: ~p, Time: ~.2fms~n", [erlang:byte_size(EncData), 
            timer:now_diff(T2, T1)/1000.0]),
    ok.


encrypt_new(Ctx, Data) ->
    encrypt_new(Ctx, Data, erlang:byte_size(Data), 100*1024, <<>>).

encrypt_new(Ctx, Data, Size, Max, Acc) when Size =< Max ->
    EncData = ecrypt_nif:cipher_update(Ctx, Data),
    Final = ecrypt_nif:cipher_final(Ctx),
    <<Acc/binary, EncData/binary, Final/binary>>;
encrypt_new(Ctx, Data, Size, Max, Acc) ->
    <<Part:Max/binary, Rest/binary>> = Data,
    EncPart = ecrypt_nif:cipher_update(Ctx, Part),
    encrypt_new(Ctx, Rest, erlang:byte_size(Rest), Max, <<Acc/binary, EncPart/binary>>).

cleanup_test() ->
    {ok, Ctx} = ecrypt_nif:new_cipher_ctx(),
    ok = ecrypt_nif:cleanup_cipher_ctx(Ctx),
    ok.

module_info_test() ->
    ecrypt_nif:module_info(),

    ok.

