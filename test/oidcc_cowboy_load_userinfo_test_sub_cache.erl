-module(oidcc_cowboy_load_userinfo_test_sub_cache).

-behaviour(oidcc_cowboy_cache).

-export([get/4]).
-export([put/5]).

get(_Type, _Token, _Req, _Env) -> {ok, #{<<"sub">> => <<"sub">>}}.

put(_Type, _Token, _Data, _Req, _Env) -> ok.
