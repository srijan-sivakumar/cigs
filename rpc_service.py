#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''Start a server and serve JSON-RPC requests.

# Workflow

## Admin:
    Loads user name into python shelf who are authorized to access the JSON-RPC
    service before serving first request.

## User:
    Only the users who are added by the admin can get a JWT token by
    sending a JSON-RPC request with parameters 'name' and 'jsessionid'
    to '/public' endpoint.

    In the subsequent requests user should pass this
    token in 'x-access-token' header to '/private' endpoint for accessing
    methods.

## Note:
    This program isn't intended to be used as it is without changing the
    business logic. Basic authentication and authorization can be taken from
    this program and your respective business logic can be implemented with
    little ease.

# Typical Usage:
    $ pipenv shell
    $ waitress-serve --port=$SERVER_PORT rpc_service:app

# Example:
    - Get a token:
    $ curl -X POST -H 'Content-Type: application/json' -d '{"id":1, \
"jsonrpc":"2.0","params":{"name": $user, "jsessionid":$cookie_string}, \
"method":"get_token"}' url:port/public

For more info refer [Github]( https://github.com/leelavg/cigs ) repo.
'''

import datetime
import logging
import os
import re
import shelve
from collections import namedtuple
from functools import wraps
from logging.handlers import RotatingFileHandler

import jwt
import requests
from dotenv import load_dotenv
from flask import Flask, Response, has_request_context, json, jsonify, request
from jira import JIRA, JIRAError
from jsonrpcserver import dispatch, method
from jsonrpcserver.exceptions import ApiError
from pygerrit2 import Anonymous, GerritRestAPI
from werkzeug.exceptions import HTTPException


# Global setup
def _validated_env_vars():
    ''' Validates environment variables.

    Takes note of Mandatory and Optional parameters passed in '.env' file and \
    stores them in a global namedtuple

    Returns:
        True if required environment variables are validated False otherwise

    Raises:
        Exception: If not all mandatory parameters required to serve the \
        requests are not specified in '.env' file
    '''

    fields = 'JIRA_SERVER JIRA_USERNAME JIRA_PASSWORD JIRA_CERT_PATH \
    GERRIT_URL POLARION_URL POLARION_REPO POLARION_USERNAME POLARION_PASSWORD \
    POLARION_PROJECT POLARION_CERT_PATH JWT_SECRET JWT_EXPIRY SERVER_PORT \
    ADMIN_USER SHELF_NAME'

    try:
        mandatory = namedtuple('Environ_man', fields)._make(
            os.getenv(field) for field in fields.split() if os.getenv(field))
    except TypeError as excep:
        raise Exception('Insufficient environment variables: ',
                        str(excep)) from excep

    # Not mandatory (optional) environment values
    fields = 'LOG_FILE LOG_SIZE LOG_BKP_COUNT'
    optional = namedtuple('Environ_opt', fields)._make(
        os.getenv(field) for field in fields.split())
    env = namedtuple('Environ', mandatory._fields + optional._fields)
    return env(*mandatory, *optional)


if not load_dotenv(dotenv_path=os.getenv('DOTENV_PATH', '.env'),
                   override=os.getenv('OVERRIDE_ENV') or False):
    raise Exception('Not able to load environment variables from file')

# Store environment variables and create Flask instance
ENV = _validated_env_vars()
app = Flask(__name__)


# Logging
# From flask logging documentation
class RequestFormatter(logging.Formatter):
    '''Log requester's remote address and request resource url too in log.'''
    def format(self, record):
        if has_request_context():
            record.url = request.url
            record.remote_addr = request.remote_addr
        else:
            record.url = None
            record.remote_addr = None

        return super().format(record)


def _get_logger(logger_name):
    '''Creates the logger for the application.

    Adds FileHandler to 'jsonrpcserver.dispatcher' and 'app' logger as well.

    Args:
        logger_name (str): Name of the logger to be created and returned

    Returns:
        A logger object with the received 'logger_name'
    '''

    # Create a custom logger
    logger = logging.getLogger(logger_name)
    log_file = ENV.LOG_FILE or 'rpc-service.log'

    # Create handlers
    file_handler = RotatingFileHandler(log_file,
                                       maxBytes=ENV.LOG_SIZE or 1e+7,
                                       backupCount=ENV.LOG_BKP_COUNT or 5)
    file_handler.setLevel(logging.INFO)

    # Create and set formatter
    formatter = RequestFormatter(
        '[%(asctime)s] %(name)s %(remote_addr)s for %(url)s '
        '%(levelname)s: %(message)s')
    file_handler.setFormatter(formatter)

    # Add handlers to logger
    logger.addHandler(file_handler)

    # Log messages from 'jsonrpcserver' as well to log file
    temp_logger = logging.getLogger('jsonrpcserver.dispatcher')
    temp_logger.addHandler(file_handler)
    temp_logger.setLevel(logging.INFO)

    # Add file handler to Flask as well and log message with new formatter
    app.logger.addHandler(file_handler)

    logger.propagate = False

    return logger


LOG = _get_logger(__name__)


# Create shelf and add ADMIN_USER
def _init_shelf():
    '''Initiates python shelve.

    Creates a new shelf if one doesn't exist to store list of users.
    '''
    with shelve.open(ENV.SHELF_NAME, writeback=True) as shelf:
        if not shelf.get('users'):
            shelf['users'] = [ENV.ADMIN_USER]
            LOG.info('Created new shelf with name %s', ENV.SHELF_NAME)


_init_shelf()

# Create required REST/SOAP client connections
jira = JIRA(basic_auth=(ENV.JIRA_USERNAME, ENV.JIRA_PASSWORD),
            options={
                'server': ENV.JIRA_SERVER,
                'verify': ENV.JIRA_CERT_PATH
            })
gerrit = GerritRestAPI(url=ENV.GERRIT_URL, auth=Anonymous())

# Pylarion SOAP client is established during import and environment variables
# has to be validated as pylarion picks credentials from there and let the
# 'Exception' stop the program execution if config is not correct
# pylint: disable=wrong-import-position
# TODO: Is it possible to cache suds client?
from pylarion.work_item import TestCase  # noqa

POL_MARKUP = '<span style="font-size: 10pt;line-height: 1.5;">{}</span>'


# Start of Helper functions
def token_required(func):
    '''Decorator to validate JWT token in http header.'''
    @wraps(func)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return {'message': 'Token is missing!'}, 401

        try:
            data = jwt.decode(token, ENV.JWT_SECRET)
            caller = data['sub']
        except jwt.exceptions.PyJWTError as excep:
            return {'message': str(excep)}, 401

        # All the functions using token will receive 'caller' as their first
        # argument
        return func(caller, *args, **kwargs)

    return decorated


# Start of basic error handling functions
@app.errorhandler(HTTPException)
def handle_http_exception(excep):
    '''Generic Error Handler for 'HTTPException'

    Args:
        excep (Exception): Type of exception raised

    Returns:
        response JSON object
    '''
    response = excep.get_response()
    response.data = json.dumps({
        'code': excep.code,
        'name': excep.name,
        'description': excep.description,
    })
    response.content_type = 'application/json'
    return response


@app.errorhandler(Exception)
def handle_exception(excep):
    '''Generic Exception handler for web requests with a pass through for \
    HTTPException.

    Args:
        excep (Exception): Type of exception raised

    Returns:
        JSON Object and Error code as a response
    '''
    code = 500
    if isinstance(excep, HTTPException):
        code = excep.code
    return jsonify(error=str(excep)), code


# Start of methods that are served at '/public' endpoint
@method
def get_token(name, jsessionid, skip_auth=False):
    '''Creates a token and returns to the caller.

    Generates a JWT token based on the info received. Cookie string will be \
    deleted after proving the user authenticity against jira server.

    Args:
        name (str): Name of the user requesting the token
        jsessionid (str): Cookie string recevied after authenticating \
        to '/rest/auth/latest/session' of Jira instance
        skip_auth (bool): Restricted to ADMIN_USER

    Raises:
        InvalidParamsError: If either 'name' or 'jsessionid' param missing \
        from JSON-RPC request
        ApiError: If the user isn't supposed to use this JSON-RPC service

    ### Example (JSON-RPC request):
        {"jsonrpc": "2.0", "method":"get_token", "params": {"name": "USERNAME",
        "jsessionid": "COOKIE_STRING"}, "id": "INTEGER/STRING"}
    '''

    with shelve.open(ENV.SHELF_NAME, flag='r') as shelf:
        if name not in shelf.get('users'):
            raise ApiError(
                'Unauthorized access', -32000,
                'Please contact admin for getting access to this service')

    if name == ENV.ADMIN_USER and skip_auth:
        # If ADMIN_USER doesn't want to be authenticated against jira
        pass
    else:
        # Authenticate user against Jira using the Cookie string
        auth_url = f'{ENV.JIRA_SERVER}/rest/auth/latest/session'
        cookies = {'JSESSIONID': jsessionid}
        resp = requests.get(auth_url,
                            cookies=cookies,
                            verify=ENV.JIRA_CERT_PATH)
        if resp:
            # Proving the identity using authenticated Jira cookie
            username = resp.json()['name']
            if name != username:
                raise ApiError(
                    'Unauthorized access', -32000,
                    f'Supplied "JSESSIONID" doesn\'t belong to {name}')

            # After authentication, logout the session which invalidates cookie
            del_ses = requests.delete(auth_url,
                                      cookies=cookies,
                                      verify=ENV.JIRA_CERT_PATH)
            if not del_ses:
                raise ApiError(
                    'Please logout of Jira once manually', -32000,
                    'Deletion of cookie failed and manual logout is needed')
        else:
            raise ApiError(
                'Invalid JSESSIONID supplied', -32000,
                f'Please contact {ENV.ADMIN_USER} for authenticating to '
                'JIRA correctly')

    # Generate and return JWT
    expiry = (datetime.datetime.utcnow() +
              datetime.timedelta(days=int(ENV.JWT_EXPIRY)))

    payload = {
        'exp': expiry,
        'sub': name,
    }
    return 'Token: ' + str(jwt.encode(payload, ENV.JWT_SECRET))


# Start of methods that are served at '/private' endpoint
@method
def add_user(context, name):
    '''Adds new user to python shelve.

    Only accessible to ADMIN_USER.

    Args:
        context (dict): A dict of form {'caller': 'CALLER_NAME'}
        name (str): Name of the user to add

    Returns:
        String response on successly adding user

    Raises:
        ApiError: If user is not authorized to this resource

    ### Example (JSON-RPC request):
        {"jsonrpc": "2.0", "method":"add_user", "params": {"name": "USERNAME"},
        "id": "INTEGER/STRING"}
    '''
    if context['caller'] == ENV.ADMIN_USER:
        with shelve.open(ENV.SHELF_NAME, writeback=True) as shelf:
            if name not in shelf.get('users'):
                shelf['users'].append(name)
                return f'{name} added to shelf'
        return f'{name} already exists in shelf'
    raise ApiError('Unauthorized access', -32000, 'Restricted to admin user')


@method
def get_all_users(context):
    '''Returns all the users stored in shelf.

    Only accessible to ADMIN_USER.

    Args:
        context (dict): A dict of form {'caller': 'CALLER_NAME'}

    Returns:
        All the users stored in shelf

    Raises:
        ApiError: If user is not authorized to this resource

    ### Example (JSON-RPC request):
        {"jsonrpc": "2.0", "method":"get_all_users", "id": "INTEGER/STRING"}
    '''
    if context['caller'] == ENV.ADMIN_USER:
        with shelve.open(ENV.SHELF_NAME, flag='r') as shelf:
            if shelf.get('users'):
                return shelf['users']
    raise ApiError('Unauthorized access', -32000, 'Restricted to admin user')


# Business logic
# pylint: disable=line-too-long
@method
def to_done(context, issue_id):
    '''Validate and update fields across Jira, Gerrit and Polarion using \
    ADMIN_USER credentials.

    Args:
        context (dict): A dict of form {'caller': 'CALLER_NAME'}
        issue_id (str): Jira Issue ID for fields updation

    Raises:
        InvalidParamsError: If 'issue_id' param is missing from JSON-RPC \
        request.

    ### Example (JSON-RPC request):
        {"jsonrpc": "2.0", "method":"to_done", "params": {"issue_id":
        "JIRA_ISSUE_ID", "id": "INTEGER/STRING"}
    '''

    # Holds all the info required to perform below operations
    info_dict = {}

    # Jira
    try:
        issue = jira.issue(issue_id, fields='summary,comment,assignee')
    except JIRAError as err:
        raise ApiError('Jira Error', -32000,
                       f'{err.status_code}: {err.text}') from err

    if issue.fields.assignee.name != context['caller']:
        raise ApiError('Not an assignee', -3200,
                       'This issue is not assigned to you')

    summary = issue.fields.summary
    info_dict['pol_id'] = summary[0:summary.find('\t')]

    comment = issue.fields.comment.comments[-1].body
    # Expects comment body as below
    # rb: 12345
    # fn: test_function_1 test_function_2
    info_dict['rb'] = re.search(r'rb: (\d+)', comment).group(0)

    # One polarion test may correspond to many 'test_' functions in worst case
    temp_fns = re.findall(r'(test_\w+)', comment)
    if not (info_dict['rb'] and temp_fns):
        raise ApiError(
            'Malformed comment body', -32000, 'Comment expression '
            'should be of form: rb: 12345\nfn: test_func_1 test_func_2')

    # Gerrit
    resp = gerrit.get(f'/changes/?q={info_dict["rb"]}')
    if resp:
        info_dict['rb_status'] = resp[0]['status']
        change_id = resp[0]['change_id']
        info_dict['fn_path'] = []
    else:
        raise ApiError(
            'Gerrit error', -32000,
            f'No patch exists in Gerrit with id: {info_dict["rb"]}')

    # Take note of test_script and function name if it is actually merged
    if info_dict['rb_status'] == 'MERGED':
        resp = gerrit.get(f'/changes/{change_id}/revisions/current/files')

        for each_file in resp.keys():
            # Don't store 'COMMIT_MSG'
            if each_file.startswith('tests'):
                # Read it's content for 'test_' functions
                file_name = each_file.replace('/', '%2F')
                # TODO: Is there a way to query only test functions without
                # reading whole file?
                resp = (
                    gerrit.get(
                        f'/changes/{change_id}/revisions/current/files/{file_name}/content'  # noqa
                    ))
                if resp:
                    # Take note of all 'test_' functions in the file
                    all_fns = re.findall(r'def (test_\w+)', resp)
                    for fn in all_fns:
                        # Check 'test_' function from file matches any function
                        # given in Jira comment and take note of the file path
                        if fn in temp_fns:
                            info_dict['fn_path'].append((fn, each_file))
        if len(info_dict['fn_path']) != temp_fns:
            raise ApiError('Patch function doesn\'t exist', -32000,
                           f'{temp_fns} doesn\'t exist in {info_dict["rb"]}')
    else:
        raise ApiError('Gerrit error', -32000,
                       f'RB: {info_dict["rb"]} is not merged')

    # Polarion
    try:
        testcase = TestCase(work_item_id=info_dict['pol_id'])
    except Exception as excep:
        raise ApiError('Polarion error', -32000, str(excep)) from excep
    if testcase.caseautomation != 'automated':
        testcase.caseautomation = 'automated'
        setattr(testcase, 'testcase-automation_id',
                ' '.join(entry[0] for entry in info_dict['fn_path']))
        script_path = '\n'.join(
            POL_MARKUP.format(entry[1]) for entry in info_dict['fn_path'])
        testcase.automation_script = script_path
        try:
            testcase.update()
        except Exception as excep:
            raise ApiError('Polarion error', -32000, str(excep)) from excep
    else:
        raise ApiError(
            'Polarion error', -32000, f'{info_dict["id"]} is '
            'already marked as "automated" in Polarion')

    # Jira
    # Transistion to 'Done' state
    # Example: To get what transistions are possible for current Jira project
    # >>> trans = jira.transitions(issue)
    # >>> available = [(t['id'], t['name']) for t in trans]; print(available)
    # >>> [('21', 'In Progress'), ('31', 'Done'), ('51', 'To Do'), ('61', 'In
    # Review')]
    # >>> jira_state = [num[0] for num in available if num[1] == 'Done' ][0]
    try:
        jira.transition_issue(issue, '31')
    except JIRAError as err:
        raise ApiError(
            'Jira Error', -32000,
            ('Polarion fields are updated but mark Jira manually to '
             '"Done", error:' + str(err))) from err

    # Add JIRA comment with gathered info if update is successful
    body = '\n'.join(
        str(key) + ': ' + str(value) for key, value in info_dict.items()
        if key not in ('rb', 'pol_id'))
    body += f'\nGerrit: {ENV.GERRIT_URL}/{info_dict["rb"]}'
    body += f'\nPolarion: {ENV.POLARION_URL}/#/project/{ENV.POLARION_PROJECT}/workitem?id={info_dict["pol_id"]}'  # noqa
    body += '\nGerrit status is verified and Polarion fields are updated'

    try:
        jira.add_comment(issue, body)
    except JIRAError as err:
        raise ApiError(
            'Jira Error', -32000,
            ('Polarion and Jira fields are updated but unable to add Jira '
             'comment' + str(err))) from err

    return 'Gerrit fields are validated, Jira and Polarion fields are updated'


@app.route('/private', methods=['POST'])
@token_required
def private(caller):
    '''Generic route for private methods which requires authentication.

    ### Currently dispatches below methods:
        get_all_users: Restricted to ADMIN_USER
        add_user: Restricted to ADMIN_USER
        to_done: Available to all authenticated users

    ### Note:
        Most of the times 'caller' will be inferred from token and
        'user' from JSON-API Call params

    ### Please refer specific method docstrings for an example API call that \
        the function accepts.
    '''
    req = request.get_data().decode()
    response = dispatch(
        req,
        context={'caller': caller},
        debug=True,
    )
    return Response(str(response),
                    response.http_status,
                    mimetype='application/json')


@app.route('/public', methods=['POST'])
def public():
    '''Generic route for public methods which doesn't require authentication.

    ### Currently dispatches below methods:
        get_token: Available to users at the discretion of ADMIN_USER

    ### Note:
        Typically used to acquire a token by proving the user identity.

    ### Please refer specific method docstrings for an example API call that \
        the function accepts.
    '''
    req = request.get_data().decode()
    response = dispatch(
        req,
        debug=True,
    )
    return Response(str(response),
                    response.http_status,
                    mimetype='application/json')
