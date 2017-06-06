# coding=utf-8
#####################################################
# THIS FILE IS AUTOMATICALLY GENERATED. DO NOT EDIT #
#####################################################
# noqa: E128,E201
from .asyncclient import AsyncBaseClient
from .asyncclient import createApiClient
from .asyncclient import config
from .asyncclient import createTemporaryCredentials
from .asyncclient import createSession
_defaultConfig = config


class Login(AsyncBaseClient):
    """
    The Login service serves as the interface between external authentication
    systems and TaskCluster credentials.  It acts as the server side of
    https://tools.taskcluster.net.  If you are working on federating logins
    with TaskCluster, this is probably *not* the service you are looking for.
    Instead, use the federated login support in the tools site.
    """

    classOptions = {
        "baseUrl": "https://login.taskcluster.net/v1"
    }

    async def ping(self, *args, **kwargs):
        """
        Ping Server

        Respond without doing anything.
        This endpoint is used to check that the service is up.

        This method is ``stable``
        """

        return await self._makeApiCall(self.funcinfo["ping"], *args, **kwargs)

    funcinfo = {
        "ping": {           'args': [],
            'method': 'get',
            'name': 'ping',
            'route': '/ping',
            'stability': 'stable'},
    }


__all__ = ['createTemporaryCredentials', 'config', '_defaultConfig', 'createApiClient', 'createSession', 'Login']
