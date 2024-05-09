%%%-------------------------------------------------------------------
%% @doc Cowboy Oidcc Callback Handler
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
%%     handle_success => fun(Req, _Token, #{<<"sub">> := Subject}) ->
%%         cowboy_req:reply(200, #{}, ["Hello ", Subject, "!"], Req)
%%     end
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
-module(oidcc_cowboy_callback).

-feature(maybe_expr, enable).

-behaviour(cowboy_handler).

-export([init/2]).
-export([terminate/3]).

-export_type([error/0]).
-export_type([opts/0]).

-type error() ::
    oidcc_client_context:error()
    | oidcc_token:error()
    | oidcc_userinfo:error()
    | useragent_mismatch
    | peer_ip_mismatch
    | {missing_request_param, Param :: binary()}.

-type opts() :: #{
    provider := gen_server:server_ref(),
    client_id := binary(),
    client_secret := binary(),
    redirect_uri := uri_string:uri_string(),
    check_useragent => boolean(),
    check_peer_ip => boolean(),
    retrieve_userinfo => boolean(),
    request_opts => oidcc_http_util:request_opts(),
    handle_success := fun(
        (
            Req :: cowboy_req:req(),
            Token :: oidcc_token:t(),
            Userinfo :: oidcc_jwt_util:claims() | undefined
        ) -> cowboy_req:req()
    ),
    handle_failure => fun((Req :: cowboy_req:req(), Reason :: error()) -> cowboy_req:req())
}.
%% Configure Token Retrieval
%%
%% See [https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint]
%%
%% <h2>Parameters</h2>
%%
%% <ul>
%%   <li>`provider' - name of the running
%%     `oidcc_provider_configuration_worker'</li>
%%   <li>`client_id' - Client ID</li>
%%   <li>`client_secret' - Client Secret</li>
%%   <li>`redirect_uri' - redirect target after authorization is completed</li>
%%   <li>`check_useragent' - check if useragent is the same as before the
%%     authorization request</li>
%%   <li>`check_peer_ip' - check if the client IP is the same as before the
%%     authorization request</li>
%%   <li>`retrieve_userinfo' - whether to load userinfo from the provider</li>
%%   <li>`request_opts' - request opts for http calls to provider</li>
%%   <li>`handle_success' - handler to react to successful token retrieval
%%     (render response etc.)</li>
%%   <li>`handle_failure' - handler to react to errors
%%     (render response etc.)</li>
%% </ul>

%% @private
-spec init(Req, Opts) -> {ok, Req, State} when
    Req :: cowboy_req:req(), Opts :: opts(), State :: nil.
init(Req, Opts) ->
    QueryList = cowboy_req:parse_qs(Req),
    {ok, BodyList, Req1} = cowboy_req:read_urlencoded_body(Req),

    RequestParams = QueryList ++ BodyList,

    ProviderId = maps:get(provider, Opts),
    ClientId = maps:get(client_id, Opts),
    ClientSecret = maps:get(client_secret, Opts),

    CheckPeerId = maps:get(check_peer_ip, Opts, true),
    CheckUseragent = maps:get(check_useragent, Opts, true),
    RetrieveUserinfo = maps:get(retrieve_userinfo, Opts, true),

    HandleSuccess = maps:get(handle_success, Opts),
    HandleFailure = maps:get(handle_failure, Opts, fun(FailureReq, _Reason) ->
        cowboy_req:reply(500, #{}, <<"internal error">>, FailureReq)
    end),

    {
        #{
            useragent := Useragent,
            peer_ip := PeerIp,
            nonce := Nonce,
            pkce_verifier := PkceVerifier
        },
        Req2
    } =
        cowboy_session:get(
            oidcc_cowboy,
            #{
                useragent => undefined,
                peer_ip => undefined,
                nonce => any,
                pkce_verifier => none
            },
            Req1
        ),

    {ok, Req3} = cowboy_session:expire(Req2),

    maybe
        ok ?= check_peer_ip(Req, PeerIp, CheckPeerId),
        ok ?= check_useragent(Req, Useragent, CheckUseragent),
        {ok, Code} ?= fetch_request_param(<<"code">>, RequestParams),
        {ok, Scopes} ?= case fetch_request_param(<<"scope">>, RequestParams) of
                            {ok, Scope} ->
                                {ok, oidcc_scope:parse(Scope)};
                            _ ->
                                case maps:get(scopes, Opts, undefined) of
                                    [_ | _] = Scps -> {ok, lists:map(fun atom_to_binary/1, Scps)};
                                    _ -> {error, {missing_request_param, <<"scope">>}}
                                end
                        end,
        TokenOpts = maps:merge(
            #{nonce => Nonce, scope => Scopes, pkce_verifier => PkceVerifier},
            maps:with([redirect_uri, pkce, request_opts], Opts)
        ),
        {ok, Token} ?=
            retrieve_token(Code, ProviderId, ClientId, ClientSecret, RetrieveUserinfo, TokenOpts),
        {ok, UserinfoClaims} ?=
            retrieve_userinfo(Token, ProviderId, ClientId, ClientSecret, RetrieveUserinfo),
        {ok, HandleSuccess(Req3, Token, UserinfoClaims), nil}
    else
        {error, Reason} ->
            {ok, HandleFailure(Req3, Reason), nil}
    end.

-spec check_peer_ip(Req, PeerIp, Check) -> ok | {error, error()} when
    Req :: cowboy_req:req(), PeerIp :: inet:ip_address() | undefined, Check :: boolean().
check_peer_ip(_Req, undefined, _Check) ->
    ok;
check_peer_ip(_Req, _PeerIp, false) ->
    ok;
check_peer_ip(Req, PeerIp, true) ->
    case cowboy_req:peer(Req) of
        {PeerIp, _Port} -> ok;
        {_OtherPeerIp, _Port} -> {error, peer_ip_mismatch}
    end.

-spec check_useragent(Req, Useragent, Check) -> ok | {error, error()} when
    Req :: cowboy_req:req(), Useragent :: binary() | undefined, Check :: boolean().
check_useragent(_Req, undefined, _Check) ->
    ok;
check_useragent(_Req, _Useragent, false) ->
    ok;
check_useragent(Req, Useragent, true) ->
    Headers = cowboy_req:headers(Req),

    case maps:get(<<"user-agent">>, Headers, undefined) of
        Useragent -> ok;
        _OtherUseragent -> {error, useragent_mismatch}
    end.

-spec fetch_request_param(Param, ParamList) ->
    {ok, unicode:chardata() | true} | {error, error()}
when
    Param :: binary(), ParamList :: oidcc_http_util:query_params().
fetch_request_param(Param, ParamList) ->
    case proplists:lookup(Param, ParamList) of
        none -> {error, {missing_request_param, Param}};
        {Param, Value} -> {ok, Value}
    end.

-spec retrieve_token(Code, ProviderId, ClientId, ClientSecret, RetrieveUserinfo, TokenOpts) ->
    {ok, oidcc_token:t()} | {error, error()}
when
    Code :: binary(),
    ProviderId :: gen_server:server_ref(),
    ClientId :: binary(),
    ClientSecret :: binary(),
    RetrieveUserinfo :: boolean(),
    TokenOpts :: oidcc_token:retrieve_opts().
retrieve_token(Code, ProviderId, ClientId, ClientSecret, RetrieveUserinfo, TokenOpts) ->
    case oidcc:retrieve_token(Code, ProviderId, ClientId, ClientSecret, TokenOpts) of
        {ok, Token} -> {ok, Token};
        {error, {none_alg_used, Token}} when RetrieveUserinfo -> {ok, Token};
        {error, Reason} -> {error, Reason}
    end.

-spec retrieve_userinfo(Token, ProviderId, ClientId, ClientSecret, RetrieveUserinfo) ->
    {ok, oidcc_jwt_util:claims() | undefined} | {error, error()}
when
    Token :: oidcc_token:t(),
    ProviderId :: gen_server:server_ref(),
    ClientId :: binary(),
    ClientSecret :: binary(),
    RetrieveUserinfo :: boolean().
retrieve_userinfo(_Token, _ProviderId, _ClientId, _ClientSecret, false) ->
    {ok, undefined};
retrieve_userinfo(Token, ProviderId, ClientId, ClientSecret, true) ->
    oidcc:retrieve_userinfo(Token, ProviderId, ClientId, ClientSecret, #{}).

%% @private
terminate(_Reason, _Req, _State) ->
    ok.
