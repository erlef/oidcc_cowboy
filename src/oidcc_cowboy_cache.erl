-module(oidcc_cowboy_cache).

-include("internal/doc.hrl").
?MODULEDOC("""
Behaviour to cache introspection / userinfo requests

## Usage

- Userinfo - See `t:oidcc_cowboy_load_userinfo:opts/0` / `cache`
- Introspection - See `t:oidcc_cowboy_introspect_token:opts/0` / `cache`
""").
?MODULEDOC(#{since => <<"2.0.0">>}).

-export_type([t/0]).

?DOC(#{since => <<"2.0.0">>}).
-type t() :: module().

?DOC(#{since => <<"2.0.0">>}).
-callback get
    (Type :: userinfo, Token :: binary(), Req :: cowboy_req:req(), Env :: cowboy_middleware:env()) ->
        {ok, oidcc_jwt_util:claims()} | miss;
    (
        Type :: introspection,
        Token :: binary(),
        Req :: cowboy_req:req(),
        Env :: cowboy_middleware:env()
    ) -> {ok, oidcc_token_introspection:t()} | miss.

?DOC(#{since => <<"2.0.0">>}).
-callback put
    (
        Type :: userinfo,
        Token :: binary(),
        Data :: oidcc_jwt_util:claims(),
        Req :: cowboy_req:req(),
        Env :: cowboy_middleware:env()
    ) ->
        ok;
    (
        Type :: introspection,
        Token :: binary(),
        Data :: oidcc_token_introspection:t(),
        Req :: cowboy_req:req(),
        Env :: cowboy_middleware:env()
    ) -> ok.
