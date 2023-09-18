-module(oidcc_cowboy_load_userinfo_test).

-include_lib("eunit/include/eunit.hrl").

validates_token_using_userinfo_test() ->
    ok = meck:new(oidcc),

    RetrieveUserinfoFun = fun(
        <<"token">>,
        config_provider,
        <<"client_id">>,
        <<"client_secret">>,
        #{}
    ) ->
        {ok, #{<<"sub">> => <<"sub">>}}
    end,
    ok = meck:expect(oidcc, retrieve_userinfo, RetrieveUserinfoFun),

    Req0 = make_req(#{oidcc_cowboy_extract_authorization => <<"token">>}),
    {ok, Req, _Env} = oidcc_cowboy_load_userinfo:execute(Req0, #{
        oidcc_cowboy_load_userinfo => #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>
        }
    }),

    ?assertMatch(#{oidcc_cowboy_load_userinfo := #{<<"sub">> := <<"sub">>}}, Req),

    true = meck:validate(oidcc),

    meck:unload(oidcc),

    ok.

skips_without_token_test() ->
    Req0 = make_req(#{oidcc_cowboy_extract_authorization => undefined}),

    {ok, Req, _Env} = oidcc_cowboy_load_userinfo:execute(Req0, #{
        oidcc_cowboy_load_userinfo => #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>
        }
    }),

    ?assertMatch(#{oidcc_cowboy_load_userinfo := undefined}, Req),

    ok.

relays_userinfo_error_test() ->
    ok = meck:new(oidcc),

    RetrieveUserinfoFun = fun(
        <<"token">>,
        config_provider,
        <<"client_id">>,
        <<"client_secret">>,
        #{}
    ) ->
        {error, reason}
    end,
    ok = meck:expect(oidcc, retrieve_userinfo, RetrieveUserinfoFun),

    Req0 = make_req(#{oidcc_cowboy_extract_authorization => <<"token">>}),

    ?assertError(
        reason,
        oidcc_cowboy_load_userinfo:execute(Req0, #{
            oidcc_cowboy_load_userinfo => #{
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

    RetrieveUserinfoFun = fun(
        <<"token">>,
        config_provider,
        <<"client_id">>,
        <<"client_secret">>,
        #{}
    ) ->
        {error, {http_error, 401, <<"invalid_token">>}}
    end,
    ok = meck:expect(oidcc, retrieve_userinfo, RetrieveUserinfoFun),

    #{streamid := Ref} = Req0 = make_req(#{oidcc_cowboy_extract_authorization => <<"token">>}),
    {stop, Req} = oidcc_cowboy_load_userinfo:execute(Req0, #{
        oidcc_cowboy_load_userinfo => #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>
        }
    }),

    ?assertMatch(#{oidcc_cowboy_load_userinfo := undefined, has_sent_resp := true}, Req),

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

    RetrieveUserinfoFun = fun(
        <<"token">>,
        config_provider,
        <<"client_id">>,
        <<"client_secret">>,
        #{}
    ) ->
        {error, {http_error, 401, <<"invalid_token">>}}
    end,
    ok = meck:expect(oidcc, retrieve_userinfo, RetrieveUserinfoFun),

    #{streamid := Ref} = Req0 = make_req(#{oidcc_cowboy_extract_authorization => <<"token">>}),
    {stop, Req} = oidcc_cowboy_load_userinfo:execute(Req0, #{
        oidcc_cowboy_load_userinfo => #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>,
            send_inactive_token_response => fun(InactiveReq0, _Env) ->
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

    ?assertMatch(#{oidcc_cowboy_load_userinfo := undefined, has_sent_resp := true}, Req),

    receive
        {{_Pid, Ref}, {response, Status, _Headers, Body}} ->
            ?assertEqual(500, Status),
            ?assertMatch(<<"invalid">>, Body)
    end,

    true = meck:validate(oidcc),

    meck:unload(oidcc),

    ok.

uses_cache_if_provided_and_found_test() ->
    Req0 = make_req(#{oidcc_cowboy_extract_authorization => <<"token">>}),
    {ok, Req, _Env} = oidcc_cowboy_load_userinfo:execute(Req0, #{
        oidcc_cowboy_load_userinfo => #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>,
            cache => oidcc_cowboy_load_userinfo_test_sub_cache
        }
    }),

    ?assertMatch(#{oidcc_cowboy_load_userinfo := #{<<"sub">> := <<"sub">>}}, Req),

    ok.

errors_without_oidcc_cowboy_extract_authorization_test() ->
    Req0 = make_req(#{}),

    ?assertError(
        no_oidcc_cowboy_extract_authorization,
        oidcc_cowboy_load_userinfo:execute(Req0, #{
            oidcc_cowboy_load_userinfo => #{
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
        oidcc_cowboy_load_userinfo:execute(Req0, #{})
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
