-module(basic_client_app).
-behaviour(application).

-export([start/2]).
-export([stop/1]).

start(_, _) ->
    ConfigEndpoint = <<"https://accounts.google.com/.well-known/openid-configuration">>,
    LocalEndpoint = <<"http://localhost:8080/oidc">>,
    Config = #{
      id => <<"google">>,
      client_id => <<"65375832888-m99kcr0vu8qq95h588b1rhi52ei234qo.apps.googleusercontent.com">>,
      client_secret =>  <<"MEfMXcaQtckJPBctTrAuSQkJ">>
     },
    {ok, _, Pid} = oidcc:add_openid_provider(ConfigEndpoint, LocalEndpoint, Config),
    ok = wait_for_config(Pid),
    basic_client:init(),
    Dispatch = cowboy_router:compile( [{'_',
                                        [
                                         {"/", basic_client_http, []},
                                         {"/oidc", oidcc_cowboy, []},
                                         {"/oidc/return", oidcc_cowboy, []}
                                        ]}]),
    {ok, _} = cowboy:start_clear(http, [{port, 8080}], #{env => #{dispatch => Dispatch}}),
    basic_client_sup:start_link().

stop(_) ->
    ok.

wait_for_config(Pid) ->
    Ready = oidcc_openid_provider:is_ready(Pid),
    {ok, Error} = oidcc_openid_provider:get_error(Pid),
    case {Ready, Error}  of
        {true, undefined} ->
            ok;
        {false, undefined} ->
            timer:sleep(100),
            wait_for_config(Pid);
        _ ->
            {error, Error}
    end.
