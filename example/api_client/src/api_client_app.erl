-module(api_client_app).
-behaviour(application).

-export([start/2]).
-export([stop/1]).

start(_, _) ->
    OidccCowboyOpts = #{
        provider => config_provider,
        client_id => <<"231448922814497203@test">>,
        client_secret => <<"B0feDwlAjnEeIfOhtIuw1mfN2oPOTnyHgRqV5KFQCMeV2O76WUUzceYjaoHSa3RY">>
    },
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/", api_client, #{}}
        ]}
    ]),
    {ok, _} = cowboy:start_clear(http, [{port, 8080}], #{
        env => #{
            dispatch => Dispatch,
            oidcc_cowboy_load_userinfo => OidccCowboyOpts,
            oidcc_cowboy_introspect_token => OidccCowboyOpts,
            oidcc_cowboy_validate_jwt_token => maps:put(client_id, <<"231402830936789415">>, OidccCowboyOpts)
        },
        middlewares => [
            oidcc_cowboy_extract_authorization,
            oidcc_cowboy_load_userinfo,
            oidcc_cowboy_introspect_token,
            oidcc_cowboy_validate_jwt_token,
            cowboy_router,
            cowboy_handler
        ]
    }),
    api_client_sup:start_link().

stop(_) ->
    ok.
