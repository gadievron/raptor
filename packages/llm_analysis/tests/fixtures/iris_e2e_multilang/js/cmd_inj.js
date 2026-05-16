const { exec } = require('child_process');
const target = process.argv[2];
exec(`ping -c1 ${target}`);
