<div style="margin-right: 15px; float: left;">
  <img
    align="left"
    src="assets/logo.svg"
    alt="OpenID Connect Logo"
    width="170px"
  />
</div>

# oidcc_cowboy

Cowboy callback module for easy integration of OpenId Connect, using [oidcc](https://github.com/erlef/oidcc).

[![EEF Security WG project](https://img.shields.io/badge/EEF-Security-black)](https://github.com/erlef/security-wg)
[![Main Branch](https://github.com/erlef/oidcc_cowboy/actions/workflows/branch_main.yml/badge.svg?branch=main)](https://github.com/erlef/oidcc_cowboy/actions/workflows/branch_main.yml)
[![Module Version](https://img.shields.io/hexpm/v/oidcc_cowboy.svg)](https://hex.pm/packages/oidcc_cowboy)
[![Total Download](https://img.shields.io/hexpm/dt/oidcc_cowboy.svg)](https://hex.pm/packages/oidcc_cowboy)
[![License](https://img.shields.io/hexpm/l/oidcc_cowboy.svg)](https://github.com/erlef/oidcc_cowboy/blob/main/LICENSE)
[![Last Updated](https://img.shields.io/github/last-commit/erlef/oidcc_cowboy.svg)](https://github.com/erlef/oidcc_cowboy/commits/master)
[![Coverage Status](https://coveralls.io/repos/github/erlef/oidcc_cowboy/badge.svg?branch=main)](https://coveralls.io/github/erlef/oidcc_cowboy?branch=main)

<br clear="left"/>

<!-- TODO: Uncomment after certification -->
<!--
<picture style="margin-right: 15px; float: left;">
  <source
    media="(prefers-color-scheme: dark)"
    srcset="assets/certified-dark.svg"
    width="170px"
    align="left"
  />
  <source
    media="(prefers-color-scheme: light)"
    srcset="assets/certified-light.svg"
    width="170px"
    align="left"
  />
  <img
    src="assets/certified-light.svg"
    alt="OpenID Connect Certified Logo"
    width="170px"
    align="left"
  />
</picture>

OpenID Certified by Jonatan Männchen at the Erlang Ecosystem Foundation for the
basic and configuration profile of the OpenID Connect protocol. For details,
check the [Conformance Documentation](https://github.com/erlef/oidcc/tree/openid-foundation-certification).

<br clear="left"/>
-->

<picture style="margin-right: 15px; float: left;">
  <source
    media="(prefers-color-scheme: dark)"
    srcset="assets/erlef-logo-dark.svg"
    width="170px"
    align="left"
  />
  <source
    media="(prefers-color-scheme: light)"
    srcset="assets/erlef-logo-light.svg"
    width="170px"
    align="left"
  />
  <img
    src="assets/erlef-logo-light.svg"
    alt="Erlang Ecosystem Foundation Logo"
    width="170px"
    align="left"
  />
</picture>

The refactoring for `v2` and the certification is funded as an
[Erlang Ecosystem Foundation](https://erlef.org/) stipend entered by the
[Security Working Group](https://erlef.org/wg/security).

<br clear="left"/>

## Usage

### Code Flow

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

### Authorization Header Checking

```erlang
-module(api_client_app).
-behaviour(application).

-export([start/2]).
-export([stop/1]).

start(_, _) ->
    OidccCowboyOpts = #{
        provider => config_provider_gen_server_name,
        client_id => <<"client_id">>,
        client_secret => <<"client_secret">>
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
            oidcc_cowboy_validate_jwt_token => OidccCowboyOpts,
        },
        middlewares => [
            oidcc_cowboy_extract_authorization,
            oidcc_cowboy_load_userinfo, %% Check Token via Userinfo
            oidcc_cowboy_introspect_token, %% Check Token via Introspection
            oidcc_cowboy_validate_jwt_token, %% Check Token via JWT validation
            cowboy_router,
            cowboy_handler
        ]
    }),
    api_client_sup:start_link().

stop(_) ->
    ok.
```