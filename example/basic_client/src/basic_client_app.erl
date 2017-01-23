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
    oidcc:add_openid_provider(ConfigEndpoint, LocalEndpoint, Config),
    basic_client:init(),
    Dispatch = cowboy_router:compile( [{'_',
        				[
        				 {"/", basic_client_http, []},
        				 {"/oidc", oidcc_cowboy, []},
        				 {"/oidc/return", oidcc_cowboy, []}
        				]}]),
    {ok, _} = cowboy:start_http( http_handler
        		       , 100
        		       , [ {port, 8080} ]
        		       , [{env, [{dispatch, Dispatch}]}]
        		       ),
    basic_client_sup:start_link().

stop(_) ->
    ok.
