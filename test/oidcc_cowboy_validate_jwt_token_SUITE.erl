-module(oidcc_cowboy_validate_jwt_token_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("oidcc/include/oidcc_token.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0]).
-export([retrieves_token/1]).

all() ->
    [retrieves_token].

retrieves_token(_Config) ->
    {ok, ConfigPid} = oidcc_provider_configuration_worker:start_link(#{
        issuer => <<"https://erlef-test-w4a8z2.zitadel.cloud">>
    }),

    JwtProfileConfigPath = code:priv_dir(oidcc_cowboy) ++ "/test/fixtures/zitadel-jwt-profile.json",
    {ok, JwtProfileConfigJson} = file:read_file(JwtProfileConfigPath),
    #{<<"key">> := Key, <<"keyId">> := Kid, <<"userId">> := Subject} = jose:decode(
        JwtProfileConfigJson
    ),

    ClientConfigPath = code:priv_dir(oidcc_cowboy) ++ "/test/fixtures/zitadel-client.json",
    {ok, ClientConfigJson} = file:read_file(ClientConfigPath),
    #{<<"clientSecret">> := ClientSecret, <<"projectId">> := ProjectId} = jose:decode(
        ClientConfigJson
    ),

    Jwk = jose_jwk:from_pem(Key),

    application:set_env(oidcc, max_clock_skew, 10),
    {ok, #oidcc_token{access = #oidcc_token_access{token = AccessToken}}} = oidcc:jwt_profile_token(
        Subject, ConfigPid, <<"231391584430604723">>, ClientSecret, Jwk, #{
            scope => [
                <<"openid">>,
                <<"urn:zitadel:iam:org:project:id:", ProjectId/binary, ":aud">>,
                <<"profile">>
            ],
            kid => Kid
        }
    ),
    application:unset_env(oidcc, max_clock_skew),

    Req0 = make_req(#{oidcc_cowboy_extract_authorization => AccessToken}),
    {ok, Req, _Env} = oidcc_cowboy_validate_jwt_token:execute(Req0, #{
        oidcc_cowboy_validate_jwt_token => #{
            provider => ConfigPid,
            client_id => ProjectId,
            client_secret => ClientSecret
        }
    }),

    ?assertMatch(
        #{
            oidcc_cowboy_validate_jwt_token := #{<<"sub">> := Subject}
        },
        Req
    ),

    ok.

make_req(Default) ->
    maps:merge(
        #{
            headers => #{<<"user-agent">> => <<"useragent">>},
            peer => {{127, 0, 0, 1}, 8080},
            pid => self(),
            streamid => make_ref()
        },
        Default
    ).
