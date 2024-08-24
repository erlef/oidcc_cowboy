-module(oidcc_cowboy_cache_noop).

-include("internal/doc.hrl").
?MODULEDOC(false).

-behaviour(oidcc_cowboy_cache).

-export([get/4]).
-export([put/5]).

get(_Type, _Token, _Req, _Env) -> miss.

put(_Type, _Token, _Data, _Req, _Env) -> ok.
