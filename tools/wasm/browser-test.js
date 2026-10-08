// Run via T3 preview evaluation locally or Playwright in CI.
(async () => {
  window.cwaTestDone = false;
  window.cwaTestError = undefined;
  const app = window.jupyterapp;
  if (!app) throw new Error('JupyterLite app is not exposed');
  console.log('CWA stage: waiting for app');
  await app.started;
  console.log('CWA stage: starting kernel');
  const kernel = await app.serviceManager.kernels.startNew({name: 'xpython'});
  console.log('CWA stage: kernel ready');
  const origin = window.location.origin;
  const source = await (await fetch('/assets/cwa-test/worker-test.py')).text();
  const code = `CWA_TEST_ORIGIN=${JSON.stringify(origin)}\n${source}`;
  window.cwaTestMessages = [];
  const request = kernel.requestExecute({code});
  request.onIOPub = msg => {
    if (msg.header.msg_type === 'stream') window.cwaTestMessages.push(msg.content.text);
    if (msg.header.msg_type === 'error') window.cwaTestMessages.push(msg.content);
  };
  try {
    await request.done;
    window.cwaTestDone = true;
  } finally {
    await kernel.shutdown();
  }
})().catch(error => {window.cwaTestError = String(error); window.cwaTestDone = true;});
