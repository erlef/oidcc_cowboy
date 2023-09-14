-module(basic_client_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    Procs = [
        #{
            id => google_config_provider,
            start =>
                {oidcc_provider_configuration_worker, start_link, [
                    #{
                        issuer => <<"https://accounts.google.com">>,
                        name => {local, google_config_provider}
                    }
                ]},
            restart => permanent,
            type => worker,
            modules => [oidcc_provider_configuration_worker]
        }
    ],
    {ok, {{one_for_one, 1, 5}, Procs}}.
