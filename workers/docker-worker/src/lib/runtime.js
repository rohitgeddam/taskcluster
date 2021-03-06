/**
Holds all runtime configuration options for the worker with various convenience
methods.
*/
let assert = require('assert');

function Runtime(options) {
  assert(typeof options === 'object', 'options must be an object.');
  for (let key of Object.keys(options || {})) {this[key] = options[key];}

  this.workerPool = `${this.provisionerId}/${this.workerType}`;

  // Ensure capacity is always a number.
  if (this.capacity) {this.capacity = parseInt(this.capacity, 10);}

  // set up to update credentials as necessary
  if (this.hostManager) {
    this.hostManager.onNewCredentials(creds => {
      this.log('Got new worker credentials', { clientId: creds.clientId });
      this.taskcluster = creds;
    });
    this.hostManager.onGracefulTermination(graceful => {
      this.log('Got graceful-termination request', { graceful });
      this.shutdownManager.onGracefulTermination(graceful);
    });
  }
}

Runtime.prototype = {
  /**
  Dockerode instance.

  @type {Dockerode}
  */
  docker: null,

  /**
  Pulse credentials `{username: '...', password: '...'}`

  @type {Object}
  */
  pulse: null,

  /**
  Capacity of the worker.

  @type {Number}
  */
  capacity: 0,

  /**
  Identifier for this worker.

  @type {String}
  */
  workerId: null,

  /**
  Type of the current worker.

  @type {String}
  */
  workerType: null,

  /**
  Pool of the current worker.

  @type {String}
  */
  workerPool: null,

  /**
  Which group of workers this worker belongs to.
  @type {String}
  */
  workerGroup: null,

  /**
  The provisioner who is responsible for this worker.
  */
  provisionerId: null,

  /**
  Host instance
  */
  hostManager: null,
};

Runtime.prototype.logEvent = function({ eventType, task = { status: {} }, timestamp }) {
  if (!timestamp) {
    timestamp = Date.now();
  }

  const eventInfo = {
    eventType,
    worker: 'docker-worker',
    workerPoolId: `${this.provisionerId}/${this.workerType}`,
    workerId: this.workerId,
    timestamp: Math.floor(timestamp / 1000),
    region: this.region,
    instanceType: this.instanceType,
    taskId: task.status.taskId,
    runId: task.runId,
  };

  if (this.instanceId !== 'test-worker-instance') {
    process.stdout.write(`\nWORKER_METRICS ${JSON.stringify(eventInfo)}\n`);
  }
};

module.exports = Runtime;
