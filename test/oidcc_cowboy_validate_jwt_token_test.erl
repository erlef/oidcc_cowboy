-module(oidcc_cowboy_validate_jwt_token_test).

-include_lib("eunit/include/eunit.hrl").

validates_token_using_jwt_test() ->
    ok = meck:new(oidcc_token),
    ok = meck:new(oidcc_client_context),

    ValidateIdTokenFun = fun(
        <<"token">>,
        client_context,
        any
    ) ->
        {ok, #{<<"sub">> => <<"sub">>}}
    end,
    ok = meck:expect(oidcc_token, validate_id_token, ValidateIdTokenFun),

    FromConfigurationWorkerFun = fun(
        config_provider,
        <<"client_id">>,
        <<"client_secret">>
    ) ->
        {ok, client_context}
    end,
    ok = meck:expect(oidcc_client_context, from_configuration_worker, FromConfigurationWorkerFun),

    Req0 = make_req(#{oidcc_cowboy_extract_authorization => <<"token">>}),
    {ok, Req, _Env} = oidcc_cowboy_validate_jwt_token:execute(Req0, #{
        oidcc_cowboy_validate_jwt_token => #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>
        }
    }),

    ?assertMatch(#{oidcc_cowboy_validate_jwt_token := #{<<"sub">> := <<"sub">>}}, Req),

    true = meck:validate(oidcc_token),
    true = meck:validate(oidcc_client_context),

    meck:unload(oidcc_token),
    meck:unload(oidcc_client_context),

    ok.

skips_without_token_test() ->
    Req0 = make_req(#{oidcc_cowboy_extract_authorization => undefined}),

    {ok, Req, _Env} = oidcc_cowboy_validate_jwt_token:execute(Req0, #{
        oidcc_cowboy_validate_jwt_token => #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>
        }
    }),

    ?assertMatch(#{oidcc_cowboy_validate_jwt_token := undefined}, Req),

    ok.

relays_validation_error_test() ->
    ok = meck:new(oidcc_token),
    ok = meck:new(oidcc_client_context),

    ValidateIdTokenFun = fun(
        <<"token">>,
        client_context,
        any
    ) ->
        {error, reason}
    end,
    ok = meck:expect(oidcc_token, validate_id_token, ValidateIdTokenFun),

    FromConfigurationWorkerFun = fun(
        config_provider,
        <<"client_id">>,
        <<"client_secret">>
    ) ->
        {ok, client_context}
    end,
    ok = meck:expect(oidcc_client_context, from_configuration_worker, FromConfigurationWorkerFun),

    Req0 = make_req(#{oidcc_cowboy_extract_authorization => <<"token">>}),

    ?assertError(
        reason,
        oidcc_cowboy_validate_jwt_token:execute(Req0, #{
            oidcc_cowboy_validate_jwt_token => #{
                provider => config_provider,
                client_id => <<"client_id">>,
                client_secret => <<"client_secret">>
            }
        })
    ),

    true = meck:validate(oidcc_token),
    true = meck:validate(oidcc_client_context),

    meck:unload(oidcc_token),
    meck:unload(oidcc_client_context),

    ok.

sends_error_response_with_inactive_token_test() ->
    ok = meck:new(oidcc_token),
    ok = meck:new(oidcc_client_context),

    ValidateIdTokenFun = fun(
        <<"token">>,
        client_context,
        any
    ) ->
        {error, token_expired}
    end,
    ok = meck:expect(oidcc_token, validate_id_token, ValidateIdTokenFun),

    FromConfigurationWorkerFun = fun(
        config_provider,
        <<"client_id">>,
        <<"client_secret">>
    ) ->
        {ok, client_context}
    end,
    ok = meck:expect(oidcc_client_context, from_configuration_worker, FromConfigurationWorkerFun),

    #{streamid := Ref} = Req0 = make_req(#{oidcc_cowboy_extract_authorization => <<"token">>}),
    {stop, Req} = oidcc_cowboy_validate_jwt_token:execute(Req0, #{
        oidcc_cowboy_validate_jwt_token => #{
            provider => config_provider,
            client_id => <<"client_id">>,
            client_secret => <<"client_secret">>
        }
    }),

    ?assertMatch(#{oidcc_cowboy_validate_jwt_token := undefined, has_sent_resp := true}, Req),

    receive
        {{_Pid, Ref}, {response, Status, _Headers, Body}} ->
            ?assertEqual(401, Status),
            ?assertMatch(<<"The provided token is inactive">>, Body)
    end,

    true = meck:validate(oidcc_token),
    true = meck:validate(oidcc_client_context),

    meck:unload(oidcc_token),
    meck:unload(oidcc_client_context),

    ok.

can_customize_inactive_token_response_test() ->
    ok = meck:new(oidcc_token),
    ok = meck:new(oidcc_client_context),

    ValidateIdTokenFun = fun(
        <<"token">>,
        client_context,
        any
    ) ->
        {error, token_expired}
    end,
    ok = meck:expect(oidcc_token, validate_id_token, ValidateIdTokenFun),

    FromConfigurationWorkerFun = fun(
        config_provider,
        <<"client_id">>,
        <<"client_secret">>
    ) ->
        {ok, client_context}
    end,
    ok = meck:expect(oidcc_client_context, from_configuration_worker, FromConfigurationWorkerFun),

    #{streamid := Ref} = Req0 = make_req(#{oidcc_cowboy_extract_authorization => <<"token">>}),
    {stop, Req} = oidcc_cowboy_validate_jwt_token:execute(Req0, #{
        oidcc_cowboy_validate_jwt_token => #{
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

    ?assertMatch(#{oidcc_cowboy_validate_jwt_token := undefined, has_sent_resp := true}, Req),

    receive
        {{_Pid, Ref}, {response, Status, _Headers, Body}} ->
            ?assertEqual(500, Status),
            ?assertMatch(<<"invalid">>, Body)
    end,

    true = meck:validate(oidcc_token),
    true = meck:validate(oidcc_client_context),

    meck:unload(oidcc_token),
    meck:unload(oidcc_client_context),

    ok.

errors_without_oidcc_cowboy_extract_authorization_test() ->
    Req0 = make_req(#{}),

    ?assertError(
        no_oidcc_cowboy_extract_authorization,
        oidcc_cowboy_validate_jwt_token:execute(Req0, #{
            oidcc_cowboy_validate_jwt_token => #{
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
        oidcc_cowboy_validate_jwt_token:execute(Req0, #{})
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
