-module(oidcc_cowboy_callback_test).

-include_lib("eunit/include/eunit.hrl").

successful_test() ->
    application:ensure_all_started(cowboy_session),

    ok = meck:new(oidcc),

    RetrieveTokenFun = fun(
        <<"code">>,
        config_provider,
        <<"client_id">>,
        <<"client_secret">>,
        #{redirect_uri := "http://localhost:8080/oidc/return", nonce := _Nonce}
    ) ->
        {ok, token}
    end,
    ok = meck:expect(oidcc, retrieve_token, RetrieveTokenFun),

    RetrieveUserinfoFun = fun(
        token,
        config_provider,
        <<"client_id">>,
        <<"client_secret">>,
        #{}
    ) ->
        {ok, #{<<"sub">> => <<"sub">>}}
    end,
    ok = meck:expect(oidcc, retrieve_userinfo, RetrieveUserinfoFun),

    #{streamid := Ref} =
        Req = make_req(#{
            qs => uri_string:compose_query([{<<"code">>, <<"code">>}, {<<"scope">>, <<"openid">>}]),
            has_read_body => true,
            multipart => []
        }),

    Req1 = set_session(Req, oidcc_cowboy, #{
        peer_ip => {127, 0, 0, 1}, useragent => <<"useragent">>, nonce => <<"nonce">>
    }),

    ?assertMatch(
        {ok, #{has_sent_resp := true}, _},
        oidcc_cowboy_callback:init(Req1, #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>,
            redirect_uri => "http://localhost:8080/oidc/return",
            handle_success => fun(SuccessReq, _Token, #{<<"sub">> := Subject}) ->
                ?assertMatch(<<"sub">>, Subject),
                cowboy_req:reply(200, #{}, ["Hello ", Subject, "!"], SuccessReq)
            end
        })
    ),

    oidcc_cowboy_callback:terminate(normal, Req1, nil),

    receive
        {{_Pid, Ref}, {response, Status, _Headers, Body}} ->
            ?assertEqual(200, Status),
            ?assertMatch(["Hello ", <<"sub">>, "!"], Body)
    end,

    true = meck:validate(oidcc),

    meck:unload(oidcc),

    ok.

ip_mismatch_test() ->
    application:ensure_all_started(cowboy_session),

    #{streamid := Ref} =
        Req = make_req(#{
            qs => uri_string:compose_query([{<<"code">>, <<"code">>}, {<<"scope">>, <<"openid">>}]),
            has_read_body => true,
            multipart => []
        }),

    Req1 = set_session(Req, oidcc_cowboy, #{
        peer_ip => {127, 0, 0, 2}, useragent => <<"useragent">>, nonce => <<"nonce">>
    }),

    ?assertMatch(
        {ok, #{has_sent_resp := true}, _},
        oidcc_cowboy_callback:init(Req1, #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>,
            redirect_uri => "http://localhost:8080/oidc/return",
            handle_failure => fun(FailureReq, peer_ip_mismatch) ->
                cowboy_req:reply(500, #{}, <<"internal error">>, FailureReq)
            end,
            handle_success => fun(_SuccessReq, _Token, _Claims) ->
                throw(should_not_reach)
            end
        })
    ),

    oidcc_cowboy_callback:terminate(normal, Req1, nil),

    receive
        {{_Pid, Ref}, {response, Status, _Headers, Body}} ->
            ?assertEqual(500, Status),
            ?assertMatch(<<"internal error">>, Body)
    end,

    ok.

missing_params_test() ->
    application:ensure_all_started(cowboy_session),

    #{streamid := Ref} =
        Req = make_req(#{
            qs => uri_string:compose_query([{<<"code">>, <<"code">>}]),
            has_read_body => true,
            multipart => []
        }),

    ?assertMatch(
        {ok, #{has_sent_resp := true}, _},
        oidcc_cowboy_callback:init(Req, #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>,
            redirect_uri => "http://localhost:8080/oidc/return",
            handle_failure => fun(FailureReq, {missing_request_param, <<"scope">>}) ->
                cowboy_req:reply(500, #{}, <<"internal error">>, FailureReq)
            end,
            handle_success => fun(_SuccessReq, _Token, _Claims) ->
                throw(should_not_reach)
            end
        })
    ),

    oidcc_cowboy_callback:terminate(normal, Req, nil),

    receive
        {{_Pid, Ref}, {response, Status, _Headers, Body}} ->
            ?assertEqual(500, Status),
            ?assertMatch(<<"internal error">>, Body)
    end,

    ok.

passes_none_alg_with_userinfo_test() ->
    application:ensure_all_started(cowboy_session),

    ok = meck:new(oidcc),

    RetrieveTokenFun = fun(
        <<"code">>,
        config_provider,
        <<"client_id">>,
        <<"client_secret">>,
        #{redirect_uri := "http://localhost:8080/oidc/return", nonce := _Nonce}
    ) ->
        {error, {none_alg_used, token}}
    end,
    ok = meck:expect(oidcc, retrieve_token, RetrieveTokenFun),

    RetrieveUserinfoFun = fun(
        token,
        config_provider,
        <<"client_id">>,
        <<"client_secret">>,
        #{}
    ) ->
        {ok, #{<<"sub">> => <<"sub">>}}
    end,
    ok = meck:expect(oidcc, retrieve_userinfo, RetrieveUserinfoFun),

    #{streamid := Ref} =
        Req = make_req(#{
            qs => uri_string:compose_query([{<<"code">>, <<"code">>}, {<<"scope">>, <<"openid">>}]),
            has_read_body => true,
            multipart => []
        }),

    Req1 = set_session(Req, oidcc_cowboy, #{
        peer_ip => {127, 0, 0, 1}, useragent => <<"useragent">>, nonce => <<"nonce">>
    }),

    ?assertMatch(
        {ok, #{has_sent_resp := true}, _},
        oidcc_cowboy_callback:init(Req1, #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>,
            redirect_uri => "http://localhost:8080/oidc/return",
            handle_success => fun(SuccessReq, _Token, #{<<"sub">> := Subject}) ->
                ?assertMatch(<<"sub">>, Subject),
                cowboy_req:reply(200, #{}, ["Hello ", Subject, "!"], SuccessReq)
            end
        })
    ),

    oidcc_cowboy_callback:terminate(normal, Req1, nil),

    receive
        {{_Pid, Ref}, {response, Status, _Headers, Body}} ->
            ?assertEqual(200, Status),
            ?assertMatch(["Hello ", <<"sub">>, "!"], Body)
    end,

    true = meck:validate(oidcc),

    meck:unload(oidcc),

    ok.

fails_none_alg_without_userinfo_test() ->
    application:ensure_all_started(cowboy_session),

    ok = meck:new(oidcc),

    RetrieveTokenFun = fun(
        <<"code">>,
        config_provider,
        <<"client_id">>,
        <<"client_secret">>,
        #{redirect_uri := "http://localhost:8080/oidc/return", nonce := _Nonce}
    ) ->
        {error, {none_alg_used, token}}
    end,
    ok = meck:expect(oidcc, retrieve_token, RetrieveTokenFun),

    #{streamid := Ref} =
        Req = make_req(#{
            qs => uri_string:compose_query([{<<"code">>, <<"code">>}, {<<"scope">>, <<"openid">>}]),
            has_read_body => true,
            multipart => []
        }),

    Req1 = set_session(Req, oidcc_cowboy, #{
        peer_ip => {127, 0, 0, 1}, useragent => <<"useragent">>, nonce => <<"nonce">>
    }),

    ?assertMatch(
        {ok, #{has_sent_resp := true}, _},
        oidcc_cowboy_callback:init(Req1, #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>,
            retrieve_userinfo => false,
            redirect_uri => "http://localhost:8080/oidc/return",
            handle_failure => fun(FailureReq, {none_alg_used, token}) ->
                cowboy_req:reply(500, #{}, <<"internal error">>, FailureReq)
            end,
            handle_success => fun(_SuccessReq, _Token, _Claims) ->
                throw(should_not_reach)
            end
        })
    ),

    oidcc_cowboy_callback:terminate(normal, Req1, nil),

    receive
        {{_Pid, Ref}, {response, Status, _Headers, Body}} ->
            ?assertEqual(500, Status),
            ?assertMatch(<<"internal error">>, Body)
    end,

    true = meck:validate(oidcc),

    meck:unload(oidcc),

    ok.

useragent_mismatch_test() ->
    application:ensure_all_started(cowboy_session),

    #{streamid := Ref} =
        Req = make_req(#{
            qs => uri_string:compose_query([{<<"code">>, <<"code">>}, {<<"scope">>, <<"openid">>}]),
            has_read_body => true,
            multipart => []
        }),

    Req1 = set_session(Req, oidcc_cowboy, #{
        peer_ip => {127, 0, 0, 1}, useragent => <<"other useragent">>, nonce => <<"nonce">>
    }),

    ?assertMatch(
        {ok, #{has_sent_resp := true}, _},
        oidcc_cowboy_callback:init(Req1, #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>,
            redirect_uri => "http://localhost:8080/oidc/return",
            handle_failure => fun(FailureReq, useragent_mismatch) ->
                cowboy_req:reply(500, #{}, <<"internal error">>, FailureReq)
            end,
            handle_success => fun(_SuccessReq, _Token, _Claims) ->
                throw(should_not_reach)
            end
        })
    ),

    oidcc_cowboy_callback:terminate(normal, Req1, nil),

    receive
        {{_Pid, Ref}, {response, Status, _Headers, Body}} ->
            ?assertEqual(500, Status),
            ?assertMatch(<<"internal error">>, Body)
    end,

    ok.

error_test() ->
    application:ensure_all_started(cowboy_session),

    ok = meck:new(oidcc),

    RetrieveTokenFun = fun(
        <<"code">>,
        config_provider,
        <<"client_id">>,
        <<"client_secret">>,
        #{redirect_uri := "http://localhost:8080/oidc/return", nonce := _Nonce}
    ) ->
        {error, provider_not_ready}
    end,
    ok = meck:expect(oidcc, retrieve_token, RetrieveTokenFun),

    #{streamid := Ref} =
        Req = make_req(#{
            qs => uri_string:compose_query([{<<"code">>, <<"code">>}, {<<"scope">>, <<"openid">>}]),
            has_read_body => true,
            multipart => []
        }),

    ?assertMatch(
        {ok, #{has_sent_resp := true}, _},
        oidcc_cowboy_callback:init(Req, #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>,
            redirect_uri => "http://localhost:8080/oidc/return",
            handle_success => fun(SuccessReq, _Token, #{<<"sub">> := Subject}) ->
                ?assertMatch(<<"sub">>, Subject),
                cowboy_req:reply(200, #{}, ["Hello ", Subject, "!"], SuccessReq)
            end
        })
    ),

    oidcc_cowboy_callback:terminate(normal, Req, nil),

    receive
        {{_Pid, Ref}, {response, Status, _Headers, Body}} ->
            ?assertEqual(500, Status),
            ?assertMatch(<<"internal error">>, Body)
    end,

    true = meck:validate(oidcc),

    meck:unload(oidcc),

    ok.

set_session(Req, Key, Value) ->
    {ok, #{
        resp_cookies := #{<<"session">> := [<<"session">>, <<"=">>, SessionId | _RestCookie]},
        headers := Headers
    }} = cowboy_session:set(Key, Value, Req),
    Req#{headers => maps:merge(Headers, #{<<"cookie">> => <<"session=", SessionId/binary>>})}.

make_req(Default) ->
    maps:merge(
        #{
            headers => #{<<"user-agent">> => <<"useragent">>},
            peer => {{127, 0, 0, 1}, 8080},
            pid => self(),
            streamid => make_ref()
        },
        Default
    ).
