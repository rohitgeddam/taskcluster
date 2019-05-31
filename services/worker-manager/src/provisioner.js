const taskcluster = require('taskcluster-client');
const Iterate = require('taskcluster-lib-iterate');
const {consume} = require('taskcluster-lib-pulse');

/**
 * Run all provisioning logic
 */
class Provisioner {
  constructor({providers, iterateConf, WorkerPool, monitor, notify, pulseClient, reference, rootUrl}) {
    this.providers = providers;
    this.WorkerPool = WorkerPool;
    this.monitor = monitor;
    this.notify = notify;
    this.pulseClient = pulseClient;
    const WorkerManagerEvents = taskcluster.createClient(reference);
    const workerManagerEvents = new WorkerManagerEvents({rootUrl});
    this.bindings = [
      workerManagerEvents.workerPoolCreated(),
      workerManagerEvents.workerPoolUpdated(),
      workerManagerEvents.workerPoolDeleted(),
    ];

    this.iterate = new Iterate({
      handler: async () => {
        await this.provision();
      },
      monitor,
      maxFailures: 10,
      watchdogTime: 0,
      waitTime: 60000,
      maxIterationTime: 300000, // We really should be making it through the list at least once every 5 minutes
      ...iterateConf,
    });
    this.iterate.on('error', () => {
      this.monitor.alert('iteration failed repeatedly; terminating process');
      process.exit(1);
    });
  }

  /**
   * Start the Provisioner
   */
  async initiate() {
    await this.providers.forAll(p => p.initiate());
    await this.iterate.start();

    this.pq = await consume({
      client: this.pulseClient,
      bindings: this.bindings,
      queueName: 'workerPoolUpdates',
    },
    this.monitor.timedHandler('notification', this.onMessage.bind(this)),
    );
  }

  /**
   * Terminate the Provisioner
   */
  async terminate() {
    if (this.pq) {
      await this.pq.stop();
      this.pq = null;
    }
    await this.iterate.stop();
    await this.providers.forAll(p => p.terminate());
  }

  async onMessage({exchange, payload}) {
    const {workerPoolId, providerId, previousProviderId} = payload;
    const workerPool = await this.WorkerPool.load({workerPoolId});
    const provider = this.providers.get(providerId);

    if (!provider) {
      // ignore messages for unknown providers
      return;
    }

    switch (exchange.split('/').pop()) {
      case 'worker-pool-created': {
        await provider.createResources({workerPool});
        break;
      }
      case 'worker-pool-updated': {
        if (providerId === previousProviderId) {
          await provider.updateResources({workerPool});
        } else {
          const previousProvider = this.providers.get(previousProviderId);
          await Promise.all([
            provider.createResources({workerPool}),
            previousProvider && previousProvider.removeResources({workerPool}),
          ]);
        }
        break;
      }
      case 'worker-pool-deleted': {
        await provider.removeResources({workerPool});
        await workerPool.remove(); // This is now gone for real
        break;
      }
      default: throw new Error(`Unknown exchange: ${exchange}`);
    }
  }

  /**
   * Run a single provisioning iteration
   */
  async provision() {
    // Any once-per-loop work a provider may want to do
    await this.providers.forAll(p => p.prepare());

    // Now for each worker pool we ask the providers to do stuff
    await this.WorkerPool.scan({}, {
      handler: async workerPool => {
        const provider = this.providers.get(workerPool.providerId);
        if (!provider) {
          this.monitor.warning(
            `Worker pool ${workerPool.workerPoolId} has unknown providerId ${workerPool.providerId}`);
          return;
        }

        await provider.provision({workerPool});

        await Promise.all(workerPool.previousProviderIds.map(async pId => {
          const provider = this.providers.get(pId);
          if (!provider) {
            this.monitor.info(
              `Worker pool ${workerPool.workerPoolId} has unknown previousProviderIds entry ${pId} (ignoring)`);
            return;
          }

          await provider.deprovision({workerPool});
        }));

        this.monitor.log.workerPoolProvisioned({
          workerPoolId: workerPool.workerPoolId,
          providerId: workerPool.providerId,
        });
      },
    });

    // Now allow providers to do whatever per-loop cleanup they may need
    await this.providers.forAll(p => p.cleanup());
  }
}

module.exports = {
  Provisioner,
};
