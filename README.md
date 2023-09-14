# oidcc_cowboy

[![EEF Security WG project](https://img.shields.io/badge/EEF-Security-black)](https://github.com/erlef/security-wg)
[![Main Branch](https://github.com/Erlang-Openid/oidcc_cowboy/actions/workflows/branch_main.yml/badge.svg?branch=main)](https://github.com/Erlang-Openid/oidcc_cowboy/actions/workflows/branch_main.yml)
[![Module Version](https://img.shields.io/hexpm/v/oidcc_cowboy.svg)](https://hex.pm/packages/oidcc_cowboy)
[![Total Download](https://img.shields.io/hexpm/dt/oidcc_cowboy.svg)](https://hex.pm/packages/oidcc_cowboy)
[![License](https://img.shields.io/hexpm/l/oidcc_cowboy.svg)](https://github.com/Erlang-Openid/oidcc_cowboy/blob/main/LICENSE)
[![Last Updated](https://img.shields.io/github/last-commit/Erlang-Openid/oidcc_cowboy.svg)](https://github.com/Erlang-Openid/oidcc_cowboy/commits/master)
[![Coverage Status](https://coveralls.io/repos/github/Erlang-Openid/oidcc_cowboy/badge.svg?branch=main)](https://coveralls.io/github/Erlang-Openid/oidcc_cowboy?branch=main)

Cowboy callback module for easy integration of OpenId Connect, using [oidcc](https://github.com/erlef/oidcc).

## Usage

```erlang
-module(basic_client_app).
-behaviour(application).

-export([start/2]).
-export([stop/1]).

start(_, _) ->
    OidccCowboyOpts = #{
        provider => config_provider_gen_server_name,
        client_id => <<"client_id">>,
        client_secret => <<"client_secret">>,
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
```