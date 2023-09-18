%%%-------------------------------------------------------------------
%% @doc Behaviour to cache introspection / userinfo requests
%%
%% <h2>Usage</h2>
%%
%% <ul>
%%   <li>Userinfo - See {@link oidcc_cowboy_load_userinfo:opts()} / `cache'</li>
%%   <li>Introspection - See {@link oidcc_cowboy_introspect_token:opts()} /
%%     `cache'</li>
%% </ul>
%% @end
%% @since 2.0.0
%%%-------------------------------------------------------------------
-module(oidcc_cowboy_cache).

-export_type([t/0]).

-type t() :: module().

-callback get
    (Type :: userinfo, Token :: binary(), Req :: cowboy_req:req(), Env :: cowboy_middleware:env()) ->
        {ok, oidcc_jwt_util:claims()} | miss;
    (
        Type :: introspection,
        Token :: binary(),
        Req :: cowboy_req:req(),
        Env :: cowboy_middleware:env()
    ) -> {ok, oidcc_token_introspection:t()} | miss.

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
