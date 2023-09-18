%%%-------------------------------------------------------------------
%% @doc Validate extracted authorization token using userinfo retrieval.
%%
%% See: [https://openid.net/specs/openid-connect-core-1_0.html#UserInfo]
%%
%% This middleware should be used together with
%% {@link oidcc_cowboy_extract_authorization}.
%%
%% This middleware will send a userinfo request for ever request. To avoid this,
%% provide a `cache' to {@link opts()}.
%%
%% <h2>Usage</h2>
%%
%% ```
%% OidccCowboyOpts = #{
%%     provider => openid_confi_provider_name,
%%     client_id => <<"client_id">>,
%%     client_secret => <<"client_secret">>
%% },
%% Dispatch = cowboy_router:compile([
%%     {'_', [
%%         %% ...
%%     ]}
%% ]),
%% {ok, _} = cowboy:start_clear(http, [{port, 8080}], #{
%%     middlewares => [
%%         oidcc_cowboy_extract_authorization,
%%         oidcc_cowboy_load_userinfo,
%%         cowboy_router,
%%         cowboy_handler
%%     ],
%%     env => #{
%%         dispatch => Dispatch,
%%         oidcc_cowboy_load_userinfo => OidccCowboyOpts
%%     }
%% })
%% '''
%% @end
%% @since 2.0.0
%%%-------------------------------------------------------------------
-module(oidcc_cowboy_load_userinfo).

-behaviour(cowboy_middleware).

-export([execute/2]).

-export_type([opts/0]).

-type opts() :: #{
    provider := gen_server:server_ref(),
    client_id := binary(),
    client_secret := binary(),
    userinfo_retrieve_opts => oidcc_userinfo:retrieve_opts(),
    cache => oidcc_cowboy_cache:t(),
    send_inactive_token_response => fun(
        (Req :: cowboy_req:req(), Env :: cowboy_middleware:env()) ->
            {ok, cowboy_req:req(), cowboy_middleware:env()} | {stop, cowboy_req:req()}
    )
}.
%% Options for the middleware
%%
%% <h2>Options</h2>
%%
%% <ul>
%%   <li>`provider' - name of the
%%     {@link oidcc_provider_configuration_worker}</li>
%%   <li>`client_id' - OAuth Client ID to use for the userinfo retrieval</li>
%%   <li>`client_secret' - OAuth Client Secret to use for the userinfo
%%     retrieval</li>
%%   <li>`userinfo_retrieve_opts' - Options to pass to userinfo loading</li>
%%   <li>`send_inactive_token_response' - Customize Error Response for inactive
%%     token</li>
%%   <li>`cache' - Cache userinfo response - See {@link oidcc_cowboy_cache}</li>
%% </ul>

%% @private
execute(#{oidcc_cowboy_extract_authorization := undefined} = Req, #{?MODULE := _Opts} = Env) ->
    {ok, maps:put(?MODULE, undefined, Req), Env};
execute(#{oidcc_cowboy_extract_authorization := Token} = Req, #{?MODULE := Opts} = Env) ->
    Provider = maps:get(provider, Opts),
    ClientId = maps:get(client_id, Opts),
    ClientSecret = maps:get(client_secret, Opts),
    UserinfoRetrieveOpts0 = maps:get(userinfo_retrieve_opts, Opts, #{}),
    UserinfoRetrieveOpts = maps:put(expected_subject, any, UserinfoRetrieveOpts0),
    SendInactiveTokenResponse = maps:get(
        send_inactive_token_response, Opts, fun send_inactive_token_response/2
    ),
    Cache = maps:get(cache, Opts, oidcc_cowboy_cache_noop),

    case Cache:get(userinfo, Token, Req, Env) of
        {ok, #{} = Claims} ->
            {ok, maps:put(?MODULE, Claims, Req), Env};
        miss ->
            case
                oidcc:retrieve_userinfo(
                    Token, Provider, ClientId, ClientSecret, UserinfoRetrieveOpts
                )
            of
                {ok, #{} = Claims} ->
                    Cache:put(userinfo, Token, Claims, Req, Env),
                    {ok, maps:put(?MODULE, Claims, Req), Env};
                {error, {http_error, 401, _Body}} ->
                    SendInactiveTokenResponse(maps:put(?MODULE, undefined, Req), Env);
                {error, Reason} ->
                    erlang:error(Reason)
            end
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
