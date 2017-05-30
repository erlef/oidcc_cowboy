# oidcc_cowboy
Cowboy callback module for easy integration of OpenId Connect, using [oidcc](https://github.com/indigo-dc/oidcc).

## Configuration
| Key | Description | Allowed Values (Default) |
| --- | --- | --- |
| check_user_agent | Ensure the user agent at the time of redirection and when comming back is the same | boolean (true) |
| check_peer_ip | Ensure the peer IP at the time of redirection and when comming back is the same | boolean (true) |
| retrieve_userinfo | Automatically also fetch the user info at login | boolean (false) |
| use_cookie | Put a cookie into the browser to add another layer of security | boolean (false) |
| secure_cookie | Add the 'secure' option to the cookie, should be used on SSL. | boolean (false) |
| session_max_age | The maximum duration of a login session in seconds | integer (180) |

All settings must be done in the 'oidcc' environment.
