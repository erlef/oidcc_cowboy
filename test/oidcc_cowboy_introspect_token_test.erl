-module(oidcc_cowboy_introspect_token_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("oidcc/include/oidcc_token_introspection.hrl").

validates_token_using_userinfo_test() ->
    ok = meck:new(oidcc),

    IntrospectTokenFun = fun(
        <<"token">>,
        config_provider,
        <<"client_id">>,
        <<"client_secret">>,
        #{}
    ) ->
        {ok, #oidcc_token_introspection{active = true}}
    end,
    ok = meck:expect(oidcc, introspect_token, IntrospectTokenFun),

    Req0 = make_req(#{oidcc_cowboy_extract_authorization => <<"token">>}),
    {ok, Req, _Env} = oidcc_cowboy_introspect_token:execute(Req0, #{
        oidcc_cowboy_introspect_token => #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>
        }
    }),

    ?assertMatch(
        #{oidcc_cowboy_introspect_token := #oidcc_token_introspection{active = true}}, Req
    ),

    true = meck:validate(oidcc),

    meck:unload(oidcc),

    ok.

skips_without_token_test() ->
    Req0 = make_req(#{oidcc_cowboy_extract_authorization => undefined}),

    {ok, Req, _Env} = oidcc_cowboy_introspect_token:execute(Req0, #{
        oidcc_cowboy_introspect_token => #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>
        }
    }),

    ?assertMatch(#{oidcc_cowboy_introspect_token := undefined}, Req),

    ok.

relays_userinfo_error_test() ->
    ok = meck:new(oidcc),

    IntrospectTokenFun = fun(
        <<"token">>,
        config_provider,
        <<"client_id">>,
        <<"client_secret">>,
        #{}
    ) ->
        {error, reason}
    end,
    ok = meck:expect(oidcc, introspect_token, IntrospectTokenFun),

    Req0 = make_req(#{oidcc_cowboy_extract_authorization => <<"token">>}),

    ?assertError(
        reason,
        oidcc_cowboy_introspect_token:execute(Req0, #{
            oidcc_cowboy_introspect_token => #{
                provider => config_provider,
                client_id => <<"client_id">>,
                client_secret => <<"client_secret">>
            }
        })
    ),

    true = meck:validate(oidcc),

    meck:unload(oidcc),

    ok.

sends_error_response_with_inactive_token_test() ->
    ok = meck:new(oidcc),

    IntrospectTokenFun = fun(
        <<"token">>,
        config_provider,
        <<"client_id">>,
        <<"client_secret">>,
        #{}
    ) ->
        {ok, #oidcc_token_introspection{active = false}}
    end,
    ok = meck:expect(oidcc, introspect_token, IntrospectTokenFun),

    #{streamid := Ref} = Req0 = make_req(#{oidcc_cowboy_extract_authorization => <<"token">>}),
    {stop, Req} = oidcc_cowboy_introspect_token:execute(Req0, #{
        oidcc_cowboy_introspect_token => #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>
        }
    }),

    ?assertMatch(
        #{
            oidcc_cowboy_introspect_token := #oidcc_token_introspection{active = false},
            has_sent_resp := true
        },
        Req
    ),

    receive
        {{_Pid, Ref}, {response, Status, _Headers, Body}} ->
            ?assertEqual(401, Status),
            ?assertMatch(<<"The provided token is inactive">>, Body)
    end,

    true = meck:validate(oidcc),

    meck:unload(oidcc),

    ok.

can_customize_inactive_token_response_test() ->
    ok = meck:new(oidcc),

    IntrospectTokenFun = fun(
        <<"token">>,
        config_provider,
        <<"client_id">>,
        <<"client_secret">>,
        #{}
    ) ->
        {ok, #oidcc_token_introspection{active = false}}
    end,
    ok = meck:expect(oidcc, introspect_token, IntrospectTokenFun),

    #{streamid := Ref} = Req0 = make_req(#{oidcc_cowboy_extract_authorization => <<"token">>}),
    {stop, Req} = oidcc_cowboy_introspect_token:execute(Req0, #{
        oidcc_cowboy_introspect_token => #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>,
            send_inactive_token_response => fun(InactiveReq0, _Env, _Introspection) ->
                InactiveReq = cowboy_req:reply(
                    500,
                    #{<<"content-type">> => <<"text/plain">>},
                    <<"invalid">>,
                    InactiveReq0
                ),
                {stop, InactiveReq}
            end
        }
    }),

    ?assertMatch(
        #{
            oidcc_cowboy_introspect_token := #oidcc_token_introspection{active = false},
            has_sent_resp := true
        },
        Req
    ),

    receive
        {{_Pid, Ref}, {response, Status, _Headers, Body}} ->
            ?assertEqual(500, Status),
            ?assertMatch(<<"invalid">>, Body)
    end,

    true = meck:validate(oidcc),

    meck:unload(oidcc),

    ok.

uses_cache_if_provided_and_found_test() ->
    Req0 = make_req(#{oidcc_cowboy_extract_authorization => <<"active token">>}),
    {ok, Req, _Env} = oidcc_cowboy_introspect_token:execute(Req0, #{
        oidcc_cowboy_introspect_token => #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>,
            cache => oidcc_cowboy_introspect_token_test_sub_cache
        }
    }),

    ?assertMatch(
        #{oidcc_cowboy_introspect_token := #oidcc_token_introspection{active = true}}, Req
    ),

    ok.

uses_cache_if_provided_and_found_invalid_test() ->
    Req0 = make_req(#{oidcc_cowboy_extract_authorization => <<"inactive token">>}),
    {stop, Req} = oidcc_cowboy_introspect_token:execute(Req0, #{
        oidcc_cowboy_introspect_token => #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>,
            cache => oidcc_cowboy_introspect_token_test_sub_cache
        }
    }),

    ?assertMatch(
        #{oidcc_cowboy_introspect_token := #oidcc_token_introspection{active = false}}, Req
    ),

    ok.

errors_without_oidcc_cowboy_extract_authorization_test() ->
    Req0 = make_req(#{}),

    ?assertError(
        no_oidcc_cowboy_extract_authorization,
        oidcc_cowboy_introspect_token:execute(Req0, #{
            oidcc_cowboy_introspect_token => #{
                provider => config_provider,
                client_id => <<"client_id">>,
                client_secret => <<"client_secret">>
            }
        })
    ),

    ok.

errors_without_config_test() ->
    Req0 = make_req(#{oidcc_cowboy_extract_authorization => <<"token">>}),

    ?assertError(
        no_config_provided,
        oidcc_cowboy_introspect_token:execute(Req0, #{})
    ),

    ok.

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
