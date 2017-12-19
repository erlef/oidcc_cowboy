-module(oidcc_cowboy).
-behaviour(cowboy_http_handler).

-export([init/3]).
-export([handle/2]).
-export([terminate/3]).

-record(state, {
          request_type = bad,
          code = undefined,
          error = undefined,
          state = undefined,
          provider = undefined,

          session = undefined,
          peer_ip = undefined,
          url_extension = #{},
          user_agent = undefined,
          referer = undefined,
          client_mod = undefined,
          use_cookie = undefined,
          cookie_data = undefined
         }).

-define(COOKIE, <<"oidcc_session">>).

init(_, Req, _Opts) ->
    try extract_args(Req) of
        {ok, Req2, State} -> {ok, Req2, State}
    catch
        _:_ ->
            Desc = <<"internal error occured">>,
            {ok, Req, #state{request_type=internal_error,
                             error = Desc
                            }}
    end.

handle(Req, #state{request_type = redirect} = State) ->
    %% redirect the client to the given provider Id
    %% set the cookie
    handle_redirect(State, Req);
handle(Req, #state{request_type = return,
                   error = undefined
                  } = State) ->
    %% the user comes back from the OpenId Connect Provider
    handle_return(Req, State);
handle(Req, #state{request_type = return, error=Desc} = State) ->
    %% the user comes back from the OpenId Connect Provider with an error
    %% redirect him to the
    Error = oidc_provider_error,
    handle_fail(Error, Desc, Req, State);
handle(Req, #state{request_type = session_not_found, error=Desc} = State) ->
    %% the user comes back from the OpenId Connect Provider
    %% but the session is not found
    Error = session_not_found,
    handle_fail(Error, Desc, Req, State);
handle(Req, #state{request_type = internal_error, error=Desc} = State) ->
    %% something unexpected happened
    Error = internal_error,
    handle_fail(Error, Desc, Req, State);
handle(Req, #state{request_type = bad_request, error=Desc} = State) ->
    Error = bad_request,
    handle_fail(Error, Desc, Req, State).

handle_redirect(#state{
                   session = Session,
                   user_agent = UserAgent,
                   peer_ip = PeerIp,
                   client_mod = ClientModId,
                   use_cookie = UseCookie,
                   url_extension = UrlExt
                  } = State, Req) ->
    ok = oidcc_session:set_user_agent(UserAgent, Session),
    ok = oidcc_session:set_peer_ip(PeerIp, Session),
    ok = oidcc_session:set_client_mod(ClientModId, Session),
    {ok, Url} = oidcc:create_redirect_for_session(Session, UrlExt),
    CookieUpdate = cookie_update_if_requested(UseCookie, Session),
    Redirect = {redirect, Url},
    Updates = [CookieUpdate, Redirect],
    {ok, Req2} = apply_updates(Updates, Req),
    {ok, Req2, State}.



handle_return(Req, #state{code = AuthCode,
                          session = Session,
                          user_agent = UserAgent,
                          peer_ip = PeerIp,
                          cookie_data = CookieData
                         } = State) ->
    {ok, Provider} = oidcc_session:get_provider(Session),
    {ok, ClientModId} = oidcc_session:get_client_mod(Session),
    try
        {ok, Pkce} = oidcc_session:get_pkce(Session),
        {ok, Nonce} = oidcc_session:get_nonce(Session),
        {ok, Scope} = oidcc_session:get_scopes(Session),
        IsUserAgent = oidcc_session:is_user_agent(UserAgent, Session),
        CheckUserAgent = application:get_env(oidcc, check_user_agent, true),
        IsPeerIp = oidcc_session:is_peer_ip(PeerIp, Session),
        CheckPeerIp = application:get_env(oidcc, check_peer_ip, true),
        CookieValid = oidcc_session:is_cookie_data(CookieData, Session),

        UserAgentValid = ((not CheckUserAgent) or IsUserAgent),
        PeerIpValid = ((not CheckPeerIp) or IsPeerIp),

        Config = #{nonce => Nonce,
                   pkce => Pkce,
                   scope => Scope
                  },
        TokenResult = oidcc:retrieve_and_validate_token(AuthCode, Provider,
                                                        Config),
        AgentInfo = create_agent_info(UserAgent, Session),
        IpInfo = create_ip_info(PeerIp, Session),
        CookieInfo = create_cookie_info(CookieData, Session),
        check_token_and_fingerprint(TokenResult,
                                    UserAgentValid, AgentInfo,
                                    PeerIpValid, IpInfo,
                                    CookieValid, CookieInfo)
    of
        {ok, VerifiedToken0} ->
            {ok, VerifiedToken} = add_configured_info(VerifiedToken0, Provider),
            {ok, Req2} = close_session_delete_cookie(Session, Req),
            EnvMap = #{req => Req2},
            {ok, UpdateList} = oidcc_client:succeeded(VerifiedToken,
                                                      ClientModId, EnvMap),
            {ok, Req3} = apply_updates(UpdateList, Req2),
            {ok, Req3, State}
    catch _:Error ->
            handle_fail(internal, Error, Req, State)
    end.

create_agent_info(UserAgentSecond, Session) ->
    {ok, UserAgentFirst} = oidcc_session:get_user_agent(Session),
    #{first => UserAgentFirst, second => UserAgentSecond}.

create_ip_info(IpSecond, Session) ->
    {ok, IpFirst} = oidcc_session:get_peer_ip(Session),
    #{first => IpFirst, second => IpSecond}.

create_cookie_info(CookieSecond, Session) ->
    {ok, CookieFirst} = oidcc_session:get_cookie_data(Session),
    #{first => CookieFirst, second => CookieSecond}.

add_configured_info(Token, Provider) ->
    GetUserInfo = application:get_env(oidcc, retrieve_userinfo, false),
    add_info_to_token(GetUserInfo, Token, Provider).



add_info_to_token(false, Token, _Provider) ->
    {ok, Token};
add_info_to_token(true, Token, Provider) ->
    Result = oidcc:retrieve_user_info(Token, Provider),
    {ok, NewToken} = insert_userinfo_in_token(Result, Token),
    add_info_to_token(false, NewToken, Provider).



insert_userinfo_in_token({ok, UserInfo}, Token) ->
    {ok, maps:put(user_info, UserInfo, Token)};
insert_userinfo_in_token( _, Token) ->
    {ok, maps:put(user_info, #{}, Token)}.



check_token_and_fingerprint({ok, VerifiedToken}, true, _, true, _, true, _) ->
    {ok, VerifiedToken};
check_token_and_fingerprint(TokenError, true, _, true, _, true, _) ->
    throw({token_invalid, TokenError});
check_token_and_fingerprint(_, false, AgentInfo, _, _, _, _) ->
    throw({bad_user_agent, AgentInfo});
check_token_and_fingerprint(_, _, _, false, IpInfo, _, _) ->
    throw({bad_peer_ip, IpInfo});
check_token_and_fingerprint(_, _, _, _, _, false, CookieInfo) ->
    throw({bad_cookie, CookieInfo}).

handle_fail(Error, Desc, Req, #state{
                                 session = Session
                                } = State) ->
    ClientModId = get_client_mod(Session),
    {ok, Req2} = close_session_delete_cookie(Session, Req),
    EnvMap = #{req => Req2},
    {ok, UpdateList} = oidcc_client:failed(Error, Desc, ClientModId, EnvMap),
    {ok, Req3} = apply_updates(UpdateList, Req2),
    {ok, Req3, State}.

get_client_mod(undefined) ->
    default;
get_client_mod(Session) ->
    {ok, ClientModId} = oidcc_session:get_client_mod(Session),
    ClientModId.



apply_updates([], Req) ->
    {ok, Req};
apply_updates([{raw, Req}], _) ->
    {ok, Req};
apply_updates([{redirect, Url}|T], Req) ->
    Header = [{<<"location">>, Url}],
    {ok, Req2} = cowboy_req:reply(302, Header, Req),
    apply_updates(T, Req2);
apply_updates([{cookie, Name, Data, Options} | T], Req) ->
    Req2 = cowboy_req:set_resp_cookie(Name, Data, Options, Req),
    apply_updates(T, Req2);
apply_updates([{none} | T], Req) ->
    apply_updates(T, Req).


cookie_update_if_requested(true, Session) ->
    CookieData =  base64url:encode(crypto:strong_rand_bytes(32)),
    ok = oidcc_session:set_cookie_data(CookieData, Session),
    MaxAge = application:get_env(oidcc, session_max_age, 180),
    {cookie, ?COOKIE, CookieData, cookie_opts(MaxAge)};
cookie_update_if_requested(_, _Session) ->
    {none}.


close_session_delete_cookie(undefined, Req) ->
    {ok, Req};
close_session_delete_cookie(Session, Req) ->
    HasCookie = not oidcc_session:is_cookie_data(undefined, Session),
    ok = oidcc_session:close(Session),
    case HasCookie of
        true ->
            apply_updates([clear_cookie()], Req);
        false ->
            {ok, Req}
    end.

clear_cookie() ->
    {cookie, ?COOKIE, <<"deleted">>, cookie_opts(0)}.

cookie_opts(MaxAge) ->
    BasicOpts = [ {http_only, true}, {max_age, MaxAge}, {path, <<"/">>}],
    add_secure(application:get_env(oidcc, secure_cookie, false), BasicOpts).

add_secure(true, BasicOpts) ->
    [{secure, true} | BasicOpts];
add_secure(_, BasicOpts) ->
    BasicOpts.

terminate(_Reason, _Req, _State) ->
    ok.

extract_args(Req) ->
    {QsList, Req1} = cowboy_req:qs_vals(Req),
    {ok, BodyQsList, Req2} = cowboy_req:body_qs(Req1),
    {Headers, Req3} = cowboy_req:headers(Req2),
    {Method, Req4} = cowboy_req:method(Req3),
    {Cookies, Req5} = cowboy_req:cookies(Req4),
    CookieData =  case lists:keyfind(?COOKIE, 1, Cookies) of
                      false -> undefined;
                      {?COOKIE, Data} -> Data
                  end,
    {{PeerIP, _Port}, Req99} = cowboy_req:peer(Req5),

    QsUpdate = #{req_method => Method,
                 req_cookie_data => CookieData
                },
    QsMap = maps:merge(create_map_from_proplist(QsList ++ BodyQsList),
                       QsUpdate),

    UserAgent = get_header(<<"user-agent">>, Headers),
    Referer = get_header(<<"referer">>, Headers),
    NewState = #state{
                  peer_ip = PeerIP,
                  user_agent = UserAgent,
                  referer = Referer
                 },
    ProviderId0  = maps:get(provider, QsMap, undefined),
    ProviderId = validate_provider(ProviderId0),
    redirect_or_login(ProviderId, QsMap, Req99, NewState).


redirect_or_login(undefined, QsMap, Req, State) ->
    perform_login(QsMap, Req, State) ;
redirect_or_login(bad_provider, _QsMap, Req, State) ->
    create_bad_provider_error(Req, State);
redirect_or_login({provider_not_ready, Id}, _QsMap, Req, State) ->
    create_provider_not_ready_error(Id, Req, State);
redirect_or_login(ProviderId, QsMap, Req, State) ->
    redirect_user_to_provider(ProviderId, QsMap, Req, State).


perform_login(QsMap, Req, State) ->
    <<"GET">> = maps:get(req_method, QsMap, undefined),
    SessionId = maps:get(state, QsMap, undefined),
    MaybeSession = oidcc_session_mgr:get_session(SessionId),
    handle_session_id_at_login(MaybeSession, QsMap, Req, State).

handle_session_id_at_login({ok, Session}, QsMap, Req, State) ->
    CookieData = maps:get(req_cookie_data, QsMap, <<>>),
    Code = maps:get(code, QsMap, undefined),
    Error = maps:get(error, QsMap, undefined),
    ReqState = maps:get(state, QsMap, undefined),
    ClientModId = maps:get(client_mod, QsMap, undefined),
    {ok, Req, State#state{request_type=return,
                          session = Session,
                          code = Code,
                          error = Error,
                          state = ReqState,
                          client_mod = ClientModId,
                          cookie_data = CookieData
                         }};
handle_session_id_at_login({error, Reason}, _QsMap, Req, State) ->
    Desc = list_to_binary(io_lib:format("session not found: ~p", [Reason])),
    {ok, Req, State#state{request_type=session_not_found, error = Desc}}.



create_bad_provider_error(Req, State) ->
    Desc = <<"unknown provider id">>,
    {ok, Req, State#state{request_type=bad_request, error = Desc}}.


create_provider_not_ready_error(Id, Req, State) ->
    Desc = list_to_binary(io_lib:format("provider ~p not ready", [Id])),
    {ok, Req, State#state{request_type=bad_request, error = Desc}}.


redirect_user_to_provider(ProviderId, QsMap, Req, State) ->
    {ok, Session} = oidcc_session_mgr:new_session(ProviderId),
    CookieDefault = application:get_env(oidcc, use_cookie, false),
    UseCookie = maps:is_key(use_cookie, QsMap) or CookieDefault,
    UrlExtensionData = maps:get(url_extension, QsMap, undefined),
    UrlExt = parse_url_extension(UrlExtensionData),
    {ok, Req, State#state{request_type = redirect, session = Session,
                          use_cookie = UseCookie, url_extension = UrlExt }}.


parse_url_extension(undefined) ->
    #{};
parse_url_extension(Data) ->
    try
        Binary = base64url:decode(Data),
        {ok, Map, _} = jsone:try_decode(Binary, [{object_format, map},
                                                 {keys, binary}]),
        true = is_map(Map),
        Map
    catch _:_ ->
            #{}
    end.




validate_provider(undefined) ->
    undefined;
validate_provider(ProviderId) ->
    case oidcc:get_openid_provider_info(ProviderId) of
        {ok, #{ready := true} } ->
            ProviderId;
        {ok, #{ready := false} } ->
            {provider_not_ready, ProviderId};
        _ ->
            bad_provider
    end.

-define(QSMAPPING, [
                    {<<"code">>, code},
                    {<<"error">>, error},
                    {<<"state">>, state},
                    {<<"provider">>, provider},
                    {<<"client_mod">>, client_mod},
                    {<<"url_extension">>, url_extension},
                    {<<"use_cookie">>, use_cookie}
                   ]).

create_map_from_proplist(List) ->
    KeyToAtom = fun({Key, Value}, Map) ->
                        NewKey = map_to_atom(Key, ?QSMAPPING),
                        maps:put(NewKey, Value, Map)
                end,
    lists:foldl(KeyToAtom, #{}, List).

map_to_atom(Key, Mapping) ->
    case lists:keyfind(Key, 1, Mapping) of
        {Key, AKey} ->
            AKey;
        _ ->
            Key
    end.

get_header(Key, Headers) ->
    case lists:keyfind(Key, 1, Headers) of
        {Key, Value} -> Value;
        false -> undefined
    end.
