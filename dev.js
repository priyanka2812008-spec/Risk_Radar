import { spawn } from 'child_process';

console.log('\n======================================================');
console.log('🛡️  STARTING RISK RADAR PLATFORM (FULL STACK)');
console.log('======================================================\n');

const isWin = process.platform === 'win32';
const npmCmd = isWin ? 'npm.cmd' : 'npm';

const backend = spawn(`${npmCmd} run dev`, {
  cwd: './backend',
  stdio: 'inherit',
  shell: true,
});

const frontend = spawn(`${npmCmd} run dev`, {
  cwd: './frontend',
  stdio: 'inherit',
  shell: true,
});

const cleanup = () => {
  console.log('\nGracefully shutting down services...');
  if (backend.pid) {
    if (isWin) {
      spawn('taskkill', ['/pid', backend.pid.toString(), '/f', '/t'], { stdio: 'ignore' });
    } else {
      backend.kill('SIGINT');
    }
  }
  if (frontend.pid) {
    if (isWin) {
      spawn('taskkill', ['/pid', frontend.pid.toString(), '/f', '/t'], { stdio: 'ignore' });
    } else {
      frontend.kill('SIGINT');
    }
  }
  process.exit(0);
};

process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);
