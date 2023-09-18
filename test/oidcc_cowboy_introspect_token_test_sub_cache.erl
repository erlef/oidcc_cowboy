-module(oidcc_cowboy_introspect_token_test_sub_cache).

-behaviour(oidcc_cowboy_cache).

-include_lib("oidcc/include/oidcc_token_introspection.hrl").

-export([get/4]).
-export([put/5]).

get(_Type, <<"active token">>, _Req, _Env) -> {ok, #oidcc_token_introspection{active = true}};
get(_Type, <<"inactive token">>, _Req, _Env) -> {ok, #oidcc_token_introspection{active = false}}.

put(_Type, _Token, _Data, _Req, _Env) -> ok.
