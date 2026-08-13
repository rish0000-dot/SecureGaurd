const { exec, spawn } = require('child_process');

// Variant 1: Direct child_process exec
app.get('/cmd-v1', (req, res) => {
  exec('ping -c 1 ' + req.query.ip);
});

// Variant 2: Indirect child_process spawn
app.get('/cmd-v2', (req, res) => {
  const args = req.body.args;
  spawn('sh', ['-c', args]);
});