-module(basic_client_http).
-behaviour(cowboy_http_handler).

-export([init/3]).
-export([handle/2]).
-export([terminate/3]).
-export([cookie_name/0]).

-define(COOKIE, <<"basic_client_session">>).

-record(state, {
	  session = undefined
	 }).


cookie_name() ->
    ?COOKIE.

init(_, Req, _Opts) ->
    try extract_args(Req) of
        {ok, Req2, State} -> {ok, Req2, State}
    catch
        _:_ -> {ok, Req, #state{}}
    end.

handle(Req, #state{session = Session } = State) ->
    %% clear the cookie again, so after a page reload one can retest it.
    Opts = [{max_age, 0},{http_only, true},{path, <<"/">>}],
    Req2 = cowboy_req:set_resp_cookie(?COOKIE, <<"deleted">>, Opts, Req),
    Req3 = cowboy_req:set_resp_body(get_body(Session), Req2),
    {ok, Req4} = cowboy_req:reply(200, Req3),
    {ok, Req4, State}.


get_body(undefined) ->
" <!DOCTYPE html>
<html lang=\"en\">
    <body>
	   you are not yet logged in, please do so by following
	   <a href=\"/oidc?provider=google\">going without cookie</a>
           </br>
	   you can also login
	   <a href=\"/oidc?provider=google&use_cookie=true\">with using a cookie</a>
           </br>
	   or use the url_extension
	   <a href=\"/oidc?provider=google&url_extension=eyJvdGhlcmtleSI6ImltcG9ydGFudCIsInByb3ZpZGVyX2hpbnQiOiJ0ZXN0aW5nIn0\">with extension</a>
    </body>
</html>
";
get_body(_) ->
"<!DOCTYPE html>
<html lang=\"en\">
    <body>
	   you are logged in
    </body>
</html>
".


terminate(_Reason, _Req, _State) ->
    ok.

extract_args(Req) ->
    {Session, Req2} = cowboy_req:cookie(?COOKIE, Req),
    NewState = #state{
		  session = Session
		 },
    {ok, Req2, NewState}.
