-module(api_client_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    Procs = [
        #{
            id => config_provider,
            start =>
                {oidcc_provider_configuration_worker, start_link, [
                    #{
                        issuer => <<"https://erlef-test-w4a8z2.zitadel.cloud">>,
                        name => {local, config_provider}
                    }
                ]},
            restart => permanent,
            type => worker,
            modules => [oidcc_provider_configuration_worker]
        }
    ],
    {ok, {{one_for_one, 1, 5}, Procs}}.
