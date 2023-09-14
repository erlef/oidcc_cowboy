-module(oidcc_cowboy_authorize_test).

-include_lib("eunit/include/eunit.hrl").

successful_test() ->
    application:ensure_all_started(cowboy_session),

    ok = meck:new(oidcc),

    CreateRedirectUrlFun = fun(
        config_provider,
        <<"client_id">>,
        <<"client_secret">>,
        #{redirect_uri := "http://localhost:8080/oidc/return", nonce := _Nonce}
    ) ->
        {ok, "http://example.com"}
    end,
    ok = meck:expect(oidcc, create_redirect_url, CreateRedirectUrlFun),

    #{streamid := Ref} = Req = make_req(),

    ?assertMatch(
        {ok, #{has_sent_resp := true}, _},
        oidcc_cowboy_authorize:init(Req, #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>,
            redirect_uri => "http://localhost:8080/oidc/return"
        })
    ),

    oidcc_cowboy_authorize:terminate(normal, Req, nil),

    receive
        {{_Pid, Ref}, {response, Status, Headers, _Body}} ->
            [[<<"session">>, <<"=">>, SessionId | _CookieRest]] = maps:get(
                <<"set-cookie">>, Headers
            ),

            SessionPid = gproc:lookup_local_name({cowboy_session, SessionId}),

            ?assertEqual(302, Status),
            ?assertEqual("http://example.com", maps:get(<<"location">>, Headers)),
            ?assertMatch(
                #{nonce := <<_/binary>>, peer_ip := {127, 0, 0, 1}, useragent := <<"useragent">>},
                cowboy_session_server:get(SessionPid, oidcc_cowboy, undefined)
            )
    end,

    true = meck:validate(oidcc),

    meck:unload(oidcc),

    ok.

error_test() ->
    application:ensure_all_started(cowboy_session),

    ok = meck:new(oidcc),

    CreateRedirectUrlFun = fun(
        config_provider,
        <<"client_id">>,
        <<"client_secret">>,
        #{redirect_uri := "http://localhost:8080/oidc/return", nonce := _Nonce}
    ) ->
        {error, provider_not_ready}
    end,
    ok = meck:expect(oidcc, create_redirect_url, CreateRedirectUrlFun),

    #{streamid := Ref} = Req = make_req(),

    ?assertMatch(
        {ok, #{has_sent_resp := true}, _},
        oidcc_cowboy_authorize:init(Req, #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>,
            redirect_uri => "http://localhost:8080/oidc/return"
        })
    ),

    oidcc_cowboy_authorize:terminate(normal, Req, nil),

    receive
        {{_Pid, Ref}, {response, Status, _Headers, Body}} ->
            ?assertEqual(500, Status),
            ?assertEqual(<<"internal error">>, Body)
    end,

    true = meck:validate(oidcc),

    meck:unload(oidcc),

    ok.

make_req() ->
    #{
        headers => #{<<"user-agent">> => <<"useragent">>},
        peer => {{127, 0, 0, 1}, 8080},
        pid => self(),
        streamid => make_ref()
    }.
