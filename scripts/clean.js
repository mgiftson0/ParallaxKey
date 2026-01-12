const fs = require('fs');
const path = require('path');

function rm(dir) {
  if (fs.existsSync(dir)) {
    fs.readdirSync(dir).forEach(f => {
      const p = path.join(dir, f);
      fs.lstatSync(p).isDirectory() ? rm(p) : fs.unlinkSync(p);
    });
    fs.rmdirSync(dir);
  }
}

rm('dist');
console.log('Cleaned dist/');