-module(basic_client_app).
-behaviour(application).

-export([start/2]).
-export([stop/1]).

start(_, _) ->
    OidccCowboyOpts = #{
        provider => google_config_provider,
        client_id => <<"65375832888-m99kcr0vu8qq95h588b1rhi52ei234qo.apps.googleusercontent.com">>,
        client_secret => <<"MEfMXcaQtckJPBctTrAuSQkJ">>,
        redirect_uri => "http://localhost:8080/oidc/return"
    },
    OidccCowboyCallbackOpts = maps:merge(OidccCowboyOpts, #{
        handle_success => fun(Req, _Token, #{<<"sub">> := Subject}) ->
            cowboy_req:reply(200, #{}, ["Hello ", Subject, "!"], Req)
        end
    }),
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/", oidcc_cowboy_authorize, OidccCowboyOpts},
            {"/oidc/return", oidcc_cowboy_callback, OidccCowboyCallbackOpts}
        ]}
    ]),
    {ok, _} = cowboy:start_clear(http, [{port, 8080}], #{
        env => #{dispatch => Dispatch}
    }),
    basic_client_sup:start_link().

stop(_) ->
    ok.
