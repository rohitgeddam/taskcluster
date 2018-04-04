# coding=utf-8
#####################################################
# THIS FILE IS AUTOMATICALLY GENERATED. DO NOT EDIT #
#####################################################
# noqa: E128,E201
from .client import BaseClient
from .client import createApiClient
from .client import config
from .client import createTemporaryCredentials
from .client import createSession
_defaultConfig = config


class EC2Manager(BaseClient):
    """
    A taskcluster service which manages EC2 instances.  This service does not understand any taskcluster concepts intrinsicaly other than using the name `workerType` to refer to a group of associated instances.  Unless you are working on building a provisioner for AWS, you almost certainly do not want to use this service
    """

    classOptions = {
        "baseUrl": "localhost:5555/v1"
    }

    def listWorkerTypes(self, *args, **kwargs):
        """
        See the list of worker types which are known to be managed

        This method is only for debugging the ec2-manager

        This method gives output: ``http://schemas.taskcluster.net/ec2-manager/v1/list-worker-types.json#``

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["listWorkerTypes"], *args, **kwargs)

    def runInstance(self, *args, **kwargs):
        """
        Run an instance

        Request an instance of a worker type

        This method takes input: ``http://schemas.taskcluster.net/ec2-manager/v1/run-instance-request.json#``

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["runInstance"], *args, **kwargs)

    def terminateWorkerType(self, *args, **kwargs):
        """
        Terminate all resources from a worker type

        Terminate all instances for this worker type

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["terminateWorkerType"], *args, **kwargs)

    def workerTypeStats(self, *args, **kwargs):
        """
        Look up the resource stats for a workerType

        Return an object which has a generic state description. This only contains counts of instances

        This method gives output: ``http://schemas.taskcluster.net/ec2-manager/v1/worker-type-resources.json#``

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["workerTypeStats"], *args, **kwargs)

    def workerTypeHealth(self, *args, **kwargs):
        """
        Look up the resource health for a workerType

        Return a view of the health of a given worker type

        This method gives output: ``http://schemas.taskcluster.net/ec2-manager/v1/health.json#``

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["workerTypeHealth"], *args, **kwargs)

    def workerTypeErrors(self, *args, **kwargs):
        """
        Look up the most recent errors of a workerType

        Return a list of the most recent errors encountered by a worker type

        This method gives output: ``http://schemas.taskcluster.net/ec2-manager/v1/errors.json#``

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["workerTypeErrors"], *args, **kwargs)

    def workerTypeState(self, *args, **kwargs):
        """
        Look up the resource state for a workerType

        Return state information for a given worker type

        This method gives output: ``http://schemas.taskcluster.net/ec2-manager/v1/worker-type-state.json#``

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["workerTypeState"], *args, **kwargs)

    def ensureKeyPair(self, *args, **kwargs):
        """
        Ensure a KeyPair for a given worker type exists

        Idempotently ensure that a keypair of a given name exists

        This method takes input: ``http://schemas.taskcluster.net/ec2-manager/v1/create-key-pair.json#``

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["ensureKeyPair"], *args, **kwargs)

    def removeKeyPair(self, *args, **kwargs):
        """
        Ensure a KeyPair for a given worker type does not exist

        Ensure that a keypair of a given name does not exist.

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["removeKeyPair"], *args, **kwargs)

    def terminateInstance(self, *args, **kwargs):
        """
        Terminate an instance

        Terminate an instance in a specified region

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["terminateInstance"], *args, **kwargs)

    def getPrices(self, *args, **kwargs):
        """
        Request prices for EC2

        Return a list of possible prices for EC2

        This method gives output: ``http://schemas.taskcluster.net/ec2-manager/v1/prices.json#``

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["getPrices"], *args, **kwargs)

    def getSpecificPrices(self, *args, **kwargs):
        """
        Request prices for EC2

        Return a list of possible prices for EC2

        This method takes input: ``http://schemas.taskcluster.net/ec2-manager/v1/prices-request.json#``

        This method gives output: ``http://schemas.taskcluster.net/ec2-manager/v1/prices.json#``

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["getSpecificPrices"], *args, **kwargs)

    def getHealth(self, *args, **kwargs):
        """
        Get EC2 account health metrics

        Give some basic stats on the health of our EC2 account

        This method gives output: ``http://schemas.taskcluster.net/ec2-manager/v1/health.json#``

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["getHealth"], *args, **kwargs)

    def getRecentErrors(self, *args, **kwargs):
        """
        Look up the most recent errors in the provisioner across all worker types

        Return a list of recent errors encountered

        This method gives output: ``http://schemas.taskcluster.net/ec2-manager/v1/errors.json#``

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["getRecentErrors"], *args, **kwargs)

    def regions(self, *args, **kwargs):
        """
        See the list of regions managed by this ec2-manager

        This method is only for debugging the ec2-manager

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["regions"], *args, **kwargs)

    def amiUsage(self, *args, **kwargs):
        """
        See the list of AMIs and their usage

        List AMIs and their usage by returning a list of objects in the form:
        {
        region: string
          volumetype: string
          lastused: timestamp
        }

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["amiUsage"], *args, **kwargs)

    def ebsUsage(self, *args, **kwargs):
        """
        See the current EBS volume usage list

        Lists current EBS volume usage by returning a list of objects
        that are uniquely defined by {region, volumetype, state} in the form:
        {
        region: string,
          volumetype: string,
          state: string,
          totalcount: integer,
          totalgb: integer,
          touched: timestamp (last time that information was updated),
        }

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["ebsUsage"], *args, **kwargs)

    def dbpoolStats(self, *args, **kwargs):
        """
        Statistics on the Database client pool

        This method is only for debugging the ec2-manager

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["dbpoolStats"], *args, **kwargs)

    def allState(self, *args, **kwargs):
        """
        List out the entire internal state

        This method is only for debugging the ec2-manager

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["allState"], *args, **kwargs)

    def sqsStats(self, *args, **kwargs):
        """
        Statistics on the sqs queues

        This method is only for debugging the ec2-manager

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["sqsStats"], *args, **kwargs)

    def purgeQueues(self, *args, **kwargs):
        """
        Purge the SQS queues

        This method is only for debugging the ec2-manager

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["purgeQueues"], *args, **kwargs)

    def apiReference(self, *args, **kwargs):
        """
        API Reference

        Generate an API reference for this service

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["apiReference"], *args, **kwargs)

    def ping(self, *args, **kwargs):
        """
        Ping Server

        Respond without doing anything.
        This endpoint is used to check that the service is up.

        This method is ``stable``
        """

        return self._makeApiCall(self.funcinfo["ping"], *args, **kwargs)

    funcinfo = {
        "allState": {
            'args': [],
            'method': 'get',
            'name': 'allState',
            'route': '/internal/all-state',
            'stability': 'experimental',
        },
        "amiUsage": {
            'args': [],
            'method': 'get',
            'name': 'amiUsage',
            'route': '/internal/ami-usage',
            'stability': 'experimental',
        },
        "apiReference": {
            'args': [],
            'method': 'get',
            'name': 'apiReference',
            'route': '/internal/api-reference',
            'stability': 'experimental',
        },
        "dbpoolStats": {
            'args': [],
            'method': 'get',
            'name': 'dbpoolStats',
            'route': '/internal/db-pool-stats',
            'stability': 'experimental',
        },
        "ebsUsage": {
            'args': [],
            'method': 'get',
            'name': 'ebsUsage',
            'route': '/internal/ebs-usage',
            'stability': 'experimental',
        },
        "ensureKeyPair": {
            'args': ['name'],
            'input': 'http://schemas.taskcluster.net/ec2-manager/v1/create-key-pair.json#',
            'method': 'get',
            'name': 'ensureKeyPair',
            'route': '/key-pairs/<name>',
            'stability': 'experimental',
        },
        "getHealth": {
            'args': [],
            'method': 'get',
            'name': 'getHealth',
            'output': 'http://schemas.taskcluster.net/ec2-manager/v1/health.json#',
            'route': '/health',
            'stability': 'experimental',
        },
        "getPrices": {
            'args': [],
            'method': 'get',
            'name': 'getPrices',
            'output': 'http://schemas.taskcluster.net/ec2-manager/v1/prices.json#',
            'route': '/prices',
            'stability': 'experimental',
        },
        "getRecentErrors": {
            'args': [],
            'method': 'get',
            'name': 'getRecentErrors',
            'output': 'http://schemas.taskcluster.net/ec2-manager/v1/errors.json#',
            'route': '/errors',
            'stability': 'experimental',
        },
        "getSpecificPrices": {
            'args': [],
            'input': 'http://schemas.taskcluster.net/ec2-manager/v1/prices-request.json#',
            'method': 'post',
            'name': 'getSpecificPrices',
            'output': 'http://schemas.taskcluster.net/ec2-manager/v1/prices.json#',
            'route': '/prices',
            'stability': 'experimental',
        },
        "listWorkerTypes": {
            'args': [],
            'method': 'get',
            'name': 'listWorkerTypes',
            'output': 'http://schemas.taskcluster.net/ec2-manager/v1/list-worker-types.json#',
            'route': '/worker-types',
            'stability': 'experimental',
        },
        "ping": {
            'args': [],
            'method': 'get',
            'name': 'ping',
            'route': '/ping',
            'stability': 'stable',
        },
        "purgeQueues": {
            'args': [],
            'method': 'get',
            'name': 'purgeQueues',
            'route': '/internal/purge-queues',
            'stability': 'experimental',
        },
        "regions": {
            'args': [],
            'method': 'get',
            'name': 'regions',
            'route': '/internal/regions',
            'stability': 'experimental',
        },
        "removeKeyPair": {
            'args': ['name'],
            'method': 'delete',
            'name': 'removeKeyPair',
            'route': '/key-pairs/<name>',
            'stability': 'experimental',
        },
        "runInstance": {
            'args': ['workerType'],
            'input': 'http://schemas.taskcluster.net/ec2-manager/v1/run-instance-request.json#',
            'method': 'put',
            'name': 'runInstance',
            'route': '/worker-types/<workerType>/instance',
            'stability': 'experimental',
        },
        "sqsStats": {
            'args': [],
            'method': 'get',
            'name': 'sqsStats',
            'route': '/internal/sqs-stats',
            'stability': 'experimental',
        },
        "terminateInstance": {
            'args': ['region', 'instanceId'],
            'method': 'delete',
            'name': 'terminateInstance',
            'route': '/region/<region>/instance/<instanceId>',
            'stability': 'experimental',
        },
        "terminateWorkerType": {
            'args': ['workerType'],
            'method': 'delete',
            'name': 'terminateWorkerType',
            'route': '/worker-types/<workerType>/resources',
            'stability': 'experimental',
        },
        "workerTypeErrors": {
            'args': ['workerType'],
            'method': 'get',
            'name': 'workerTypeErrors',
            'output': 'http://schemas.taskcluster.net/ec2-manager/v1/errors.json#',
            'route': '/worker-types/<workerType>/errors',
            'stability': 'experimental',
        },
        "workerTypeHealth": {
            'args': ['workerType'],
            'method': 'get',
            'name': 'workerTypeHealth',
            'output': 'http://schemas.taskcluster.net/ec2-manager/v1/health.json#',
            'route': '/worker-types/<workerType>/health',
            'stability': 'experimental',
        },
        "workerTypeState": {
            'args': ['workerType'],
            'method': 'get',
            'name': 'workerTypeState',
            'output': 'http://schemas.taskcluster.net/ec2-manager/v1/worker-type-state.json#',
            'route': '/worker-types/<workerType>/state',
            'stability': 'experimental',
        },
        "workerTypeStats": {
            'args': ['workerType'],
            'method': 'get',
            'name': 'workerTypeStats',
            'output': 'http://schemas.taskcluster.net/ec2-manager/v1/worker-type-resources.json#',
            'route': '/worker-types/<workerType>/stats',
            'stability': 'experimental',
        },
    }


__all__ = ['createTemporaryCredentials', 'config', '_defaultConfig', 'createApiClient', 'createSession', 'EC2Manager']
