%% @author Maas-Maarten Zeeman <mmzeeman@xs4all.nl>
%% @copyright 2015 Maas-Maarten Zeeman

%% @doc Erlang API for OpenSSL's evp crypto interface 

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

-module(ecrypt).
-author("Maas-Maarten Zeeman <mmzeeman@xs4all.nl>").

-export([open/5]).
-export([update/2]).
-export([final/1]).

-export([init/1, device_loop/2]).

open(Cipher, Key, Iv, Encrypt, Padding) ->
    {ok, Ctx} = ecrypt_nif:new_cipher_ctx(),
    ok = ecrypt_nif:cipher_init(Ctx, Cipher, Key, Iv, Encrypt, Padding),
    {ok, erlang:spawn_link(?MODULE, init, [Ctx])}.

update(CryptoDevice, Data) ->
    CryptoDevice ! {update, Data, self()},
    receive
        {ok, Answer} -> 
            {ok, Answer}
    end.

final(CryptoDevice) ->
    CryptoDevice ! {final, self()},
    receive
        {ok, Answer} -> {ok, Answer}
    end.


%%
%% Cipher Device
%%

init(Ctx) ->
    device_loop(Ctx, 100*1024).

device_loop(Ctx, ChunkSize) ->
    receive
        {update, Data, Rec} -> 
            InData = iolist_to_binary(Data),
            Data1 = update(Ctx, InData, erlang:byte_size(InData), ChunkSize, <<>>),
            Rec ! {ok, Data1},
            device_loop(Ctx, ChunkSize);
        {final, Rec} ->
            Data1 = ecrypt_nif:cipher_final(Ctx),
            ok = ecrypt_nif:cleanup_cipher_ctx(Ctx),
            Rec ! {ok, Data1}
    end.

%%
%% Helpers
%%

update(Ctx, Data, Size, Max, Acc) when Size > Max ->
    <<Part:Max/binary, Rest/binary>> = Data,
    EncPart = ecrypt_nif:cipher_update(Ctx, Part),
    update(Ctx, Rest, erlang:byte_size(Rest), Max, <<Acc/binary, EncPart/binary>>);
update(Ctx, Data, _Size, Max, Acc) ->
    EncData = ecrypt_nif:cipher_update(Ctx, Data),
    Final = ecrypt_nif:cipher_final(Ctx),
    <<Acc/binary, EncData/binary, Final/binary>>.

