const db = require('./database');

async function start() {
  await db.initialize();
  const app = require('./app');
  const port = Number.parseInt(process.env.PORT || '3000', 10);
  const server = app.listen(port, () => {
    console.log(`Task tracking API listening on http://localhost:${port}`);
  });

  function shutdown() {
    server.close(() => {
      db.close();
      process.exit(0);
    });
  }

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

start().catch((error) => {
  console.error('Unable to start the task tracking API:', error);
  process.exitCode = 1;
});
