%%%-------------------------------------------------------------------
%% @doc Cowboy Oidcc Authorization Handler
%%
%% <h2>Usage</h2>
%%
%% ```
%% OidccCowboyOpts = #{
%%     provider => config_provider_gen_server_name,
%%     client_id => <<"client_id">>,
%%     client_secret => <<"client_secret">>,
%%     redirect_uri => "http://localhost/oidc/return"
%% },
%% OidccCowboyCallbackOpts = maps:merge(OidccCowboyOpts, #{
%%     %% ...
%% }),
%% Dispatch = cowboy_router:compile([
%%     {'_', [
%%         {"/", oidcc_cowboy_authorize, OidccCowboyOpts},
%%         {"/oidc/return", oidcc_cowboy_callback, OidccCowboyCallbackOpts}
%%     ]}
%% ]),
%% {ok, _} = cowboy:start_clear(http, [{port, 8080}], #{
%%     env => #{dispatch => Dispatch}
%% })
%% '''
%% @end
%% @since 2.0.0
%%%-------------------------------------------------------------------
-module(oidcc_cowboy_authorize).

-feature(maybe_expr, enable).

-behaviour(cowboy_handler).

-export([init/2]).
-export([terminate/3]).

-export_type([error/0]).
-export_type([opts/0]).

-type error() :: oidcc_client_context:error() | oidcc_authorization:error().

-type opts() :: #{
    provider := gen_server:server_ref(),
    client_id := binary(),
    client_secret := binary(),
    redirect_uri := uri_string:uri_string(),
    scopes => oidcc_scope:scopes(),
    state => binary(),
    pkce => oidcc_authorization:pkce() | undefined,
    url_extension => oidcc_http_util:query_params(),
    handle_failure => fun((Req :: cowboy_req:req(), Reason :: error()) -> cowboy_req:req())
}.
%% Configure authorization redirection
%%
%% See [https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest]
%%
%% <h2>Parameters</h2>
%%
%% <ul>
%%   <li>`provider' - name of the running
%%     `oidcc_provider_configuration_worker'</li>
%%   <li>`client_id' - Client ID</li>
%%   <li>`client_secret' - Client Secret</li>
%%   <li>`redirect_uri' - redirect target after authorization is completed</li>
%%   <li>`scopes' - list of scopes to request
%%     (defaults to `[<<"openid">>]')</li>
%%   <li>`state' - state to pass to the provider</li>
%%   <li>`pkce' - pkce arguments to pass to the provider</li>
%%   <li>`url_extension' - add custom query parameters to the authorization
%%     url</li>
%%   <li>`handle_failure' - handler to react to errors
%%     (render response etc.)</li>
%% </ul>

%% @private
-spec init(Req, Opts) -> {ok, Req, State} when
    Req :: cowboy_req:req(), Opts :: opts(), State :: nil.
init(Req, Opts) ->
    Headers = cowboy_req:headers(Req),

    {PeerIp, _Port} = cowboy_req:peer(Req),
    Useragent = maps:get(<<"user-agent">>, Headers, undefined),

    ProviderId = maps:get(provider, Opts),
    ClientId = maps:get(client_id, Opts),
    ClientSecret = maps:get(client_secret, Opts),

    HandleFailure = maps:get(handle_failure, Opts, fun(FailureReq, _Reason) -> cowboy_req:reply(500, #{}, <<"internal error">>, FailureReq) end),

    Nonce = generate_nonce(),

    AuthorizationOpts = maps:merge(#{nonce => Nonce}, maps:with([redirect_uri, scopes, state, pkce, url_extension], Opts)),

    maybe
        {ok, Req1} ?= cowboy_session:set(oidcc_cowboy, #{nonce => Nonce, peer_ip => PeerIp, useragent => Useragent}, Req),

        {ok, Url} ?= oidcc:create_redirect_url(ProviderId, ClientId, ClientSecret, AuthorizationOpts),

        Req2 = cowboy_req:reply(302, #{<<"location">> => Url}, <<>>, Req1),

        {ok, Req2, nil}
    else
        {error, Reason} ->
            {ok, HandleFailure(Req, Reason), nil}
    end.

-spec generate_nonce() -> binary().
generate_nonce() ->
    base64:encode(
        crypto:strong_rand_bytes(128), #{mode => urlsafe, padding => false}
    ).

%% @private
terminate(_Reason, _Req, _State) ->
    ok.
