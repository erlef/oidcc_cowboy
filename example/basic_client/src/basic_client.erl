-module(basic_client).
-behaviour(oidcc_client).

-export([init/0]).
-export([login_succeeded/1]).
-export([login_succeeded/2]).
-export([login_failed/2]).
-export([login_failed/3]).
-export([start_debug/1, stop_debug/0]).

init() ->
    oidcc_client:register(?MODULE).

login_succeeded(Token) ->
    login_succeeded(Token, #{}).

login_succeeded(Token, EnvMap) ->
    io:format("~n~n*************************************~nthe user logged in with~n ~p~n", [Token]),
    io:format("Env: ~p~n~n***************************************~n", [EnvMap]),
    % create e.g. a session and store it't id in a session to look it up on further usage
    SessionId = <<"123">>,
    CookieName = basic_client_http:cookie_name(),
    CookieData = SessionId,
    Path = <<"/">>,
    Updates = [
               {redirect, Path},
               {cookie, CookieName, CookieData, #{max_age => 30}}
              ],
    {ok, Updates}.


login_failed(Error, Desc) ->
    login_failed(Error, Desc, #{}).

login_failed(Error, Desc, EnvMap) ->
    io:format("~n~n*************************************~nlogin failed with~n ~p:~p~n", [Error, Desc]),
    io:format("Env: ~p~n~n***************************************~n", [EnvMap]),
    Path = <<"/">>,
    Updates = [{redirect, Path}],
    {ok, Updates}.


start_debug(ModuleList) ->
    Options = [{time, 60000}, {msgs, 10000}],
    redbug:start(ModuleList, Options).

stop_debug() ->
    redbug:stop().
