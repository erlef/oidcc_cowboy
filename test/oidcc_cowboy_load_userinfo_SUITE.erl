-module(oidcc_cowboy_load_userinfo_SUITE).

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
    #{<<"clientId">> := ClientId, <<"clientSecret">> := ClientSecret, <<"projectId">> := ProjectId} = jose:decode(
        ClientConfigJson
    ),

    Jwk = jose_jwk:from_pem(Key),

    {ok, #oidcc_token{access = #oidcc_token_access{token = AccessToken}}} = oidcc:jwt_profile_token(
        Subject, ConfigPid, ClientId, ClientSecret, Jwk, #{
            scope => [
                <<"urn:zitadel:iam:org:project:id:", ProjectId/binary, ":aud">>,
                <<"profile">>
            ],
            kid => Kid
        }
    ),

    Req0 = make_req(#{oidcc_cowboy_extract_authorization => AccessToken}),
    {ok, Req, _Env} = oidcc_cowboy_load_userinfo:execute(Req0, #{
        oidcc_cowboy_load_userinfo => #{
            provider => ConfigPid,
            client_id => ClientId,
            client_secret => ClientSecret
        }
    }),

    ?assertMatch(#{oidcc_cowboy_load_userinfo := #{<<"name">> := <<"JWT Profile Test">>}}, Req),

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
