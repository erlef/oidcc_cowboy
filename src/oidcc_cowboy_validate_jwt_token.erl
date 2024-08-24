-module(oidcc_cowboy_validate_jwt_token).

-feature(maybe_expr, enable).

-include("internal/doc.hrl").
?MODULEDOC("""
Validate extracted authorization token by validating it as a JWT token.

This middleware should be used together with `m:oidcc_cowboy_extract_authorization`.

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
        oidcc_cowboy_validate_jwt_token,
        cowboy_router,
        cowboy_handler
    ],
    env => #{
        dispatch => Dispatch,
        oidcc_cowboy_validate_jwt_token => OidccCowboyOpts
    }
})
```
""").
?MODULEDOC(#{since => <<"2.0.0">>}).

-behaviour(cowboy_middleware).

-export([execute/2]).

-export_type([opts/0]).

?DOC("""
Options for the middleware

## Options

- `provider` - name of the `m:oidcc_provider_configuration_worker`
- `client_id` - OAuth Client ID to use for the token validation
- `client_secret` - OAuth Client Secret to use for the token validation
- `send_inactive_token_response` - Customize Error Response for inactive token
""").
?DOC(#{since => <<"2.0.0">>}).
-type opts() :: #{
    provider := gen_server:server_ref(),
    client_id := binary(),
    client_secret := binary(),
    send_inactive_token_response => fun(
        (Req :: cowboy_req:req(), Env :: cowboy_middleware:env()) ->
            {ok, cowboy_req:req(), cowboy_middleware:env()} | {stop, cowboy_req:req()}
    )
}.

?DOC(false).
execute(#{oidcc_cowboy_extract_authorization := undefined} = Req, #{?MODULE := _Opts} = Env) ->
    {ok, maps:put(?MODULE, undefined, Req), Env};
execute(#{oidcc_cowboy_extract_authorization := Token} = Req, #{?MODULE := Opts} = Env) ->
    Provider = maps:get(provider, Opts),
    ClientId = maps:get(client_id, Opts),
    ClientSecret = maps:get(client_secret, Opts),
    SendInactiveTokenResponse = maps:get(
        send_inactive_token_response, Opts, fun send_inactive_token_response/2
    ),

    maybe
        {ok, ClientContext} ?=
            oidcc_client_context:from_configuration_worker(Provider, ClientId, ClientSecret),
        {ok, Claims} ?= oidcc_token:validate_id_token(Token, ClientContext, any),
        {ok, maps:put(?MODULE, Claims, Req), Env}
    else
        {error, token_expired} ->
            SendInactiveTokenResponse(maps:put(?MODULE, undefined, Req), Env);
        {error, Reason} ->
            erlang:error(Reason)
    end;
execute(#{oidcc_cowboy_extract_authorization := _Token} = _Req, #{} = _Env) ->
    erlang:error(no_config_provided);
execute(#{} = _Req, #{?MODULE := _Opts} = _Env) ->
    erlang:error(no_oidcc_cowboy_extract_authorization).

send_inactive_token_response(Req0, _Env) ->
    Req = cowboy_req:reply(
        401,
        #{<<"content-type">> => <<"text/plain">>},
        <<"The provided token is inactive">>,
        Req0
    ),
    {stop, Req}.
