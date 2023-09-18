%%%-------------------------------------------------------------------
%% @doc Extract `authorization' request header
%%
%% This middleware should be used together with
%% {@link oidcc_cowboy_introspect_token}, {@link oidcc_cowboy_load_userinfo} or
%% {@link oidcc_cowboy_validate_jwt_token}.
%%
%% <h2>Usage</h2>
%%
%% ```
%% OidccCowboyOpts = #{
%%     %% ...
%% },
%% Dispatch = cowboy_router:compile([
%%     {'_', [
%%         %% ...
%%     ]}
%% ]),
%% {ok, _} = cowboy:start_clear(http, [{port, 8080}], #{
%%     middlewares => [
%%         oidcc_cowboy_extract_authorization,
%%         oidcc_cowboy_load_userinfo, %% Check Token via Introspection
%%         oidcc_cowboy_introspect_token, %% Check Token via Userinfo
%%         oidcc_cowboy_validate_jwt_token, %% Check Token via JWT validation
%%         cowboy_router,
%%         cowboy_handler
%%     ],
%%     env => #{
%%         dispatch => Dispatch,
%%         oidcc_cowboy_extract_authorization => #{}, %% Opts
%%     }
%% })
%% '''
%% @end
%% @since 2.0.0
%%%-------------------------------------------------------------------
-module(oidcc_cowboy_extract_authorization).

-behaviour(cowboy_middleware).

-export([execute/2]).

-export_type([opts/0]).

-type opts() :: #{
    send_invalid_header_response => fun(
        (Req :: cowboy_req:req(), Env :: cowboy_middleware:env(), GivenHeader :: binary()) ->
            {ok, cowboy_req:req(), cowboy_middleware:env()} | {stop, cowboy_req:req()}
    )
}.
%% Options for the middleware
%%
%% <h2>Options</h2>
%%
%% <ul>
%%   <li>`send_invalid_header_response' - Customize Error Response for invalid
%%     header</li>
%% </ul>

%% @private
execute(Req, #{?MODULE := Opts} = Env) ->
    SendInvalidHeaderResponse = maps:get(
        send_invalid_header_response, Opts, fun send_invalid_header_response/3
    ),
    case cowboy_req:headers(Req) of
        #{<<"authorization">> := <<"Bearer ", Token/binary>>} ->
            {ok, maps:put(oidcc_cowboy_extract_authorization, Token, Req), Env};
        #{<<"authorization">> := Authorization} ->
            SendInvalidHeaderResponse(Req, Env, Authorization);
        #{} ->
            {ok, maps:put(oidcc_cowboy_extract_authorization, undefined, Req), Env}
    end;
execute(Req, Env) ->
    execute(Req, maps:put(?MODULE, #{}, Env)).

send_invalid_header_response(Req0, _Env, GivenHeader) ->
    Req = cowboy_req:reply(
        400,
        #{<<"content-type">> => <<"text/plain">>},
        <<"Invalid authorization Header\n\nExpected: Authorization: Bearer <token>\nGiven: ",
            GivenHeader/binary>>,
        Req0
    ),
    {stop, Req}.
