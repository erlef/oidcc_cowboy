-module(oidcc_cowboy_introspect_token).

-include("internal/doc.hrl").
?MODULEDOC("""
Validate extracted authorization token using introspection.

See: https://datatracker.ietf.org/doc/html/rfc7662

This middleware should be used together with
`m:oidcc_cowboy_extract_authorization`.

This middleware will send a introspection request for ever request. To avoid
this, provide a `cache` to `t:opts/0`.

## Usage

```erlang
OidccCowboyOpts = #{
    provider => openid_confi_provider_name,
    client_id => <<"client_id">>,
    client_secret => <<"client_secret">>
},
Dispatch = cowboy_router:compile([
    {'_', [
        %% ...
    ]}
]),
{ok, _} = cowboy:start_clear(http, [{port, 8080}], #{
    middlewares => [
        oidcc_cowboy_extract_authorization,
        oidcc_cowboy_introspect_token,
        cowboy_router,
        cowboy_handler
    ],
    env => #{
        dispatch => Dispatch,
        oidcc_cowboy_introspect_token => OidccCowboyOpts
    }
})
```
""").
?MODULEDOC(#{since => <<"2.0.0">>}).

-behaviour(cowboy_middleware).

-include_lib("oidcc/include/oidcc_token_introspection.hrl").

-export([execute/2]).

-export_type([opts/0]).

?DOC("""
Options for the middleware

## Options

- `provider` - name of the `m:oidcc_provider_configuration_worker`
- `client_id` - OAuth Client ID to use for the token introspection
- `client_secret` - OAuth Client Secret to use for the token introspection
- `token_introspection_opts` - Options to pass to the introspection
- `send_inactive_token_response` - Customize Error Response for inactive token
- `cache` - Cache introspection response - See `m:oidcc_cowboy_cache`
""").
?DOC(#{since => <<"2.0.0">>}).
-type opts() :: #{
    provider := gen_server:server_ref(),
    client_id := binary(),
    client_secret := binary(),
    token_introspection_opts => oidcc_token_introspection:opts(),
    cache => oidcc_cowboy_cache:t(),
    send_inactive_token_response => fun(
        (
            Req :: cowboy_req:req(),
            Env :: cowboy_middleware:env(),
            Introspection :: oidcc_token_introspection:t()
        ) -> {ok, cowboy_req:req(), cowboy_middleware:env()} | {stop, cowboy_req:req()}
    )
}.

?DOC(false).
execute(#{oidcc_cowboy_extract_authorization := undefined} = Req, #{?MODULE := _Opts} = Env) ->
    {ok, maps:put(?MODULE, undefined, Req), Env};
execute(#{oidcc_cowboy_extract_authorization := Token} = Req, #{?MODULE := Opts} = Env) ->
    Provider = maps:get(provider, Opts),
    ClientId = maps:get(client_id, Opts),
    ClientSecret = maps:get(client_secret, Opts),
    TokenIntrospectionOpts = maps:get(token_introspection_opts, Opts, #{}),
    SendInactiveTokenResponse = maps:get(
        send_inactive_token_response, Opts, fun send_inactive_token_response/3
    ),
    Cache = maps:get(cache, Opts, oidcc_cowboy_cache_noop),

    case Cache:get(introspection, Token, Req, Env) of
        {ok, #oidcc_token_introspection{active = true} = Introspection} ->
            {ok, maps:put(?MODULE, Introspection, Req), Env};
        {ok, #oidcc_token_introspection{active = false} = Introspection} ->
            SendInactiveTokenResponse(maps:put(?MODULE, Introspection, Req), Env, Introspection);
        miss ->
            case
                oidcc:introspect_token(
                    Token, Provider, ClientId, ClientSecret, TokenIntrospectionOpts
                )
            of
                {ok, #oidcc_token_introspection{active = true} = Introspection} ->
                    Cache:put(introspection, Token, Introspection, Req, Env),
                    {ok, maps:put(?MODULE, Introspection, Req), Env};
                {ok, #oidcc_token_introspection{active = false} = Introspection} ->
                    SendInactiveTokenResponse(
                        maps:put(?MODULE, Introspection, Req), Env, Introspection
                    );
                {error, Reason} ->
                    erlang:error(Reason)
            end
    end;
execute(#{oidcc_cowboy_extract_authorization := _Token} = _Req, #{} = _Env) ->
    erlang:error(no_config_provided);
execute(#{} = _Req, #{?MODULE := _Opts} = _Env) ->
    erlang:error(no_oidcc_cowboy_extract_authorization).

send_inactive_token_response(Req0, _Env, _Introspection) ->
    Req = cowboy_req:reply(
        401,
        #{<<"content-type">> => <<"text/plain">>},
        <<"The provided token is inactive">>,
        Req0
    ),
    {stop, Req}.
