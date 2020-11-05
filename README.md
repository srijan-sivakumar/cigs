# CI Glue Script
## Foreword
The program in this repo **isn't** intented to be used without any modifications and so no packaging options are provided. It contains a flask based app with simple authorization and authentication scheme. The service is supposed to be run behind a firewall/VPN as this possibly access your production environment.

## Background
The abstract was proposed to [qecamp](https://www.qecamp.com/proposals/27/2221)(Make sure to follow correct link after login) and this script is the implementation of that proposal.
Below resources are available to only Red Hat associates (links are coming soon):
- [Slide deck]
- [Talk]

## Installation
### For Admin:
Production:
```
$ pip3 install pipenv
$ git clone https://github.com/leelavg/cigs.git
$ cd cigs && pipenv shell
(cigs) $ pipenv install --ignore-pipfile
```

Fill all the required details as mentioned in `.env.example` file and create a new function as per your requirements by following the [references](https://github.com/leelavg/cigs#references) and observing `to_done` function in *rpc_service.py*.

Start the service as `(cigs) $ waitress --port=$SERVER_PORT rpc_service:app`

Development/Testing:
```
$ pip3 install pipenv
$ git clone https://github.com/leelavg/cigs.git
$ cd cigs && pipenv shell
(cigs) $ pipenv install --dev
```

Perform any modifications if needed and start the server as:
`(cigs) $ SHELF_NAME=<TEST_SHELF> FLASK_ENV=development TESTING=True flask run`

Run tests as: `(cigs) $ SHELF_NAME=<SAME_AS_ABOVE> perl test_rpc_service.pl` and typical o/p is as below:
```
(cigs) $ SHELF_NAME=test_store.db perl test_rpc_service.pl 
========== START ==========
ok 1 - Test: Python shelf exists in current directory
ok 2 - Test: Two cookies should be set from jira when authenticated
ok 3 - Test: User should be able to use JSESSION ID to authenticate against Jira
[...]
ok 21 - Test: User should provide valid issue id to mark the fields
ok 22 - Test: Private ep should only be accessed with token
ok 23 - Test: Make sure no fake user is added by end of test
1..23
========== END ==========
```

Linters and fixers used for python `isort -> yapf -> flake8 -> pylint` and for perl `$ perltidy -b -pt=2 -vmll test_rpc_service.pl`

#### Note:
- At the moment you many not be able to install all the dependecies needed as it contains an internal package which is soon to be open sourced at [pylero](https://github.com/RedHatQE/pylero).
- Make sure to use different names for `SHELF_NAME` in production and testing.
- Make sure to add name of shelve's being used to `.gitignore`

### For User:

Access to a terminal(and obviously be online) is the only requirement for consuming rpc_service, please refer [Examples](https://github.com/leelavg/cigs#examples) for more info.

## Documentation

Generated from [pdoc](https://pdoc3.github.io/pdoc/) and saved to [rpc_service.html](html/rpc_service.html), run `~/cigs $ python -m http.server -d html`and access your browser for documentation.

For live documentation, install dev dependencies too, run `(cigs) $ pdoc3 -http : rpc_service.py` and point your browser to `localhost:8080`.

## Examples

### General
The service will not store any credentials and works based on JWT tokens, however to prove the identity of user it leverages Jira authentication. A cookie (JSESSIONID) should be supplied to the service which will be validated against Jira and a token is returned to user.

Cookie string can be captured from logging into your Jira account, access `<JIRA_SERVER>/rest/auth/latest/session` url, perform a refresh and view the cookies from developer tools in most of the web browsers.

Note: Cookie will be invalidated after proving the identity for security purposes. You can install [httpie](https://httpie.io/) as an alternative to curl for JSON request/response cycle.

Get token:
`curl -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0", "method":"get_token", "params": {"name":<USERNAME>, "jsession":<JSESSIONID>}, "id":<int/str>}' <url:port>/public`

#### For Admin:

Add user:
`curl -X POST -H 'Content-Type: application/json' -H 'x-access-token: <TOKEN>' -d '{"id":<int/str>,"method":"add_user","params": {"name":<USERNAME>},"jsonrpc":"2.0"}' <url:port>/private`

Get all users:
`curl -X POST -H 'Content-Type: application/json' -H 'x-access-token: <TOKEN>' -d '{"id":<int/str>,"method":"get_all_users","jsonrpc":"2.0"}' <url:port>/private`

#### For Users:

Perform actual operation for validating/updating fields (current function `to_done` is specific to one use case and roll yours according to your needs)

`curl -X POST -H 'Content-Type: application/json' -H 'x-access-token: <TOKEN>' -d '{"id":<int/str>,"method":"to_done","params": {"issue_id":<JIRA_ISSUE_ID>},"jsonrpc":"2.0"}' <url:port>/private`


## References

Apart from the documentation of python packages, please refer below to create your own methods for combining Jira, Gerrit and Polarion.
- [Jira Rest API](https://docs.atlassian.com/software/jira/docs/api/REST/7.6.1/)
- [Gerrit Rest API](https://gerrit-review.googlesource.com/Documentation/rest-api.html)
- [Pylero](https://github.com/RedHatQE/pylero) Coming very soon ...

## Get in touch

For more info, raise a github issue or contact by any means mentioned in [bio](https://github.com/leelavg) or reach out to me internally for quick response.
