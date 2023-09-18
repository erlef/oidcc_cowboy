-module(api_client).

-behaviour(cowboy_handler).

-export([init/2]).

init(#{oidcc_cowboy_load_userinfo := undefined} = Req0, State) ->
    Req = cowboy_req:reply(200,
        #{<<"content-type">> => <<"text/plain">>},
        <<"Hello anonymous User!">>,
        Req0),
    {ok, Req, State};
init(#{oidcc_cowboy_load_userinfo := #{<<"name">> := Name}} = Req0, State) ->
    Req = cowboy_req:reply(200,
        #{<<"content-type">> => <<"text/plain">>},
        <<"Hello ", Name/binary, "!">>,
        Req0),
    {ok, Req, State}.
