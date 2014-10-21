"""This module is used to interact with taskcluster rest apis"""

import sys
import os
import json
import logging
import functools
import copy
import urlparse
import time


# For finding apis.json
from pkg_resources import resource_string
import requests
# import hawk

import exceptions

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
# Only for debugging XXX: turn off the True or thing when shipping
if True or os.environ.get('DEBUG_TASKCLUSTER_CLIENT'):
  log.addHandler(logging.StreamHandler())
log.addHandler(logging.NullHandler())

API_CONFIG = json.loads(resource_string(__name__, 'apis.json'))


class Client(object):
  """ Instances of this class are API helpers for a specific API reference.
  They know how to load their data from either a statically defined JSON file
  which is packaged with the library, or by reading an environment variable can
  load the individual api endpoints from the web

  A difference between the JS and Python client is that the payload for JS
  client is always the last argument in the API method.  That works nicely
  because JS doesn't have keyword arguments.  Python does have kwargs and I'd
  like to support them (because I like to use them). The result is that I'm
  going to make the payload a mandatory keyword argument for methods which have
  an input schema.

  Failing API calls which are connection or server related (i.e. 500 series
  errors) will be retried up to a maximum number of times with an exponential
  backoff.  This functionality mirrors that of the JS Client library.  Success
  and errors which aren't connection related are returned on the first
  iteration.
  """

  _defaultOptions = {
    'credentials': {
      'clientId': os.environ.get('TASKCLUSTER_CLIENT_ID'),
      'accessToken': os.environ.get('TASKCLUSTER_ACCESS_TOKEN')
    },
    'authorization': {
      'delegating': False,
      'scopes': []
    },
    'maxRetries': 5
  }

  @property
  def options(self):
    if not hasattr(self, '_options'):
      self._options = {}
    self._options.update(self._defaultOptions)
    return self._options

  def __init__(self, apiName, api):
    """ Initialize an API Client based on its definition """
    self._options = {}

    log.debug('Creating a client object for %s', apiName)

    self.name = apiName

    ref = api['reference']


    # I wonder if anyone cares about this?
    if os.environ.get('TASKCLUSTER_CLIENT_LIVE_API'):
      ref = json.loads(requests.get(config['referenceUrl']).text)

    # API level defaults.  Ideally
    for opt in [x for x in ref if x != 'entries']:
      self.options[opt] = ref[opt]
    
    for entry in [x for x in ref['entries'] if x['type'] == 'function']:
      apiFunc = entry['name']
      log.info('Creating instance method %s.%s.%s', __name__, apiName, apiFunc)

      def addApiCall(evt):
        assert not hasattr(self, apiFunc)
        setattr(self, apiFunc, lambda *args, **kwargs:
                self._makeApiCall(evt, *args, **kwargs))

      addApiCall(entry)

  def _makeApiCall(self, entry, *args, **kwargs):
    """ This function is used to dispatch calls to other functions
    for a given API Reference entry"""

    payload = None

    # I forget if **ing a {} results in a new {} or a reference
    _kwargs = copy.deepcopy(kwargs)
    if 'input' in entry and 'payload' in _kwargs:
      payload = _kwargs['payload']
      del _kwargs['payload']
      log.debug('We have a payload!')

    apiArgs = self._processArgs(entry['args'], *args, **_kwargs)
    route = self._subArgsInRoute(entry['route'], apiArgs)
    log.debug('Route is: %s', route)

    return self._makeHttpRequest(entry['method'], route, payload)

  def _processArgs(self, reqArgs, *args, **kwargs):
    """ Take the list of required arguments, positional arguments
    and keyword arguments and return a dictionary which maps the
    value of the given arguments to the required parameters.

    Keyword arguments will overwrite positional arguments.
    """

    data = {}

    # We know for sure that if we don't give enough arguments that the call
    # should fail.  We don't yet know if we should fail because of two many
    # arguments because we might be overwriting positional ones with kw ones
    if len(reqArgs) > len(args) + len(kwargs):
      raise exceptions.TaskclusterFailure('API Method was not given enough args')

    # We also need to error out when we have more positional args than required
    # because we'll need to go through the lists of provided and required args
    # at the same time.  Not disqualifying early means we'll get IndexErrors if
    # there are more positional arguments than required
    if len(args) > len(reqArgs):
      raise exceptions.TaskclusterFailure('API Method was called with too many positional args')

    i = 0
    for arg in args:
      log.debug('Found a positional argument: %s', arg)
      data[reqArgs[i]] = arg
      i += 1

    log.debug('After processing positional arguments, we have: %s', data)

    data.update(kwargs)

    log.debug('After keyword arguments, we have: %s', data)

    if len(reqArgs) != len(data):
      errMsg = 'API Method takes %d args, %d given' % (len(reqArgs), len(data))
      log.error(errMsg)
      raise exceptions.TaskclusterFailure(errMsg)

    for reqArg in reqArgs:
      if reqArg not in data:
        errMsg = 'API Method requires a "%s" argument' % reqArg
        log.error(errMsg)
        raise exceptions.TaskclusterFailure(errMsg)

    return data

  def _subArgsInRoute(self, route, args):
    """ Given a route like "/task/<taskId>/artifacts" and a mapping like
    {"taskId": "12345"}, return a string like "/task/12345/artifacts"
    """

    if route.count('<') != route.count('>'):
      raise exceptions.TaskclusterFailure('Mismatched arguments in route')

    if route.count('<') != len(args):
      raise exceptions.TaskclusterFailure('Incorrect number of arguments for route')

    # TODO: Let's just pretend this is a good idea
    try:
      route = route.replace('<', '%(').replace('>', ')s') % args
    except KeyError as e:
      raise exceptions.TaskclusterFailure('Argument not found in route')
    return route.lstrip('/')

  def _makeHttpRequest(self, method, route, payload):
    """ Make an HTTP Request for the API endpoint.  This method wraps
    the logic about doing failure retry and passes off the actual work
    of doing an HTTP request to another method."""

    baseUrl = self.options['baseUrl']
    # urljoin ignores the last param of the baseUrl if the base url doesn't end
    # in /.  I wonder if it's better to just do something basic like baseUrl +
    # route instead
    if not baseUrl.endswith('/'):
      baseUrl += '/'
    fullUrl = urlparse.urljoin(baseUrl, route.lstrip('/'))
    log.debug('Full URL used is: %s', fullUrl)

    retry = 0
    response = None
    while retry < self.options['maxRetries']:
      log.debug('Making attempt %d', retry)
      response = self._makeSingleHttpRequest(method, fullUrl, payload)

      # We only want to consider connection errors for retry.  Other errors,
      # like a 404 saying that a resource wasn't found should be returned
      # immediately
      if response.status_code >= 500 and response.status_code < 600:
        log.error('Received HTTP Status %d, retrying', response.status_code)
        retry += 1
        snooze = float(retry * retry) / 10.0
        log.info('Sleeping %0.2f seconds for exponential backoff', snooze)
        time.sleep(snooze)
      else:
        break

    # We want to send JSON data back to the caller
    try:
      # We want to make sure that calling code handles errors
      response.raise_for_status()
      apiData = response.json()
    except requests.exceptions.RequestException as rerr:
      errStr = 'Request failed to complete'
      log.error(errStr)
      raise exceptions.TaskclusterRestFailure(errStr, superExc=rerr)
    except ValueError as ve:
      errStr = 'Response contained malformed JSON data'
      log.error(errStr)
      raise exceptions.TaskclusterRestFailure(errStr, superExc=ve, res=response)

    return apiData

  def _makeSingleHttpRequest(self, method, url, payload):
    log.debug('Making a %s request to %s', method, url)
    return requests.request(method, url, data=payload)


# This has to be done after the Client class is declared
THIS_MODULE = sys.modules[__name__]
for key, value in list(API_CONFIG.items()):
  setattr(THIS_MODULE, key, Client(key, value))
setattr(THIS_MODULE, 'config', Client._defaultOptions)
