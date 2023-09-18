-module(oidcc_cowboy_extract_authorization_test).

-include_lib("eunit/include/eunit.hrl").

extracts_token_test_test() ->
    Req = make_req(#{headers => #{<<"authorization">> => <<"Bearer token">>}}),

    ?assertMatch(
        {ok, #{oidcc_cowboy_extract_authorization := <<"token">>}, _},
        oidcc_cowboy_extract_authorization:execute(Req, #{})
    ),

    ok.

ignores_missing_header_test() ->
    Req = make_req(#{}),

    ?assertMatch(
        {ok, #{oidcc_cowboy_extract_authorization := undefined}, _},
        oidcc_cowboy_extract_authorization:execute(Req, #{})
    ),

    ok.

errors_on_malformed_header_test() ->
    #{streamid := Ref} =
        Req = make_req(#{headers => #{<<"authorization">> => <<"invalid_value">>}}),

    ?assertMatch(
        {stop, #{has_sent_resp := true}},
        oidcc_cowboy_extract_authorization:execute(Req, #{})
    ),

    receive
        {{_Pid, Ref}, {response, Status, _Headers, Body}} ->
            ?assertEqual(400, Status),
            ?assertMatch(
                <<"Invalid authorization Header\n\nExpected: Authorization: Bearer <token>\nGiven: invalid_value">>,
                Body
            )
    end,

    ok.

can_override_error_test() ->
    #{streamid := Ref} =
        Req = make_req(#{headers => #{<<"authorization">> => <<"invalid_value">>}}),

    ?assertMatch(
        {stop, #{has_sent_resp := true}},
        oidcc_cowboy_extract_authorization:execute(Req, #{
            oidcc_cowboy_extract_authorization => #{
                send_invalid_header_response => fun(ErrorReq0, _Env, <<"invalid_value">>) ->
                    ErrorReq = cowboy_req:reply(400, #{}, <<"invalid">>, ErrorReq0),
                    {stop, ErrorReq}
                end
            }
        })
    ),

    receive
        {{_Pid, Ref}, {response, Status, _Headers, Body}} ->
            ?assertEqual(400, Status),
            ?assertMatch(<<"invalid">>, Body)
    end,

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
