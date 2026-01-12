const fs = require('fs');
const path = require('path');

function deleteDir(dirPath) {
  if (fs.existsSync(dirPath)) {
    fs.readdirSync(dirPath).forEach(file => {
      const curPath = path.join(dirPath, file);
      fs.lstatSync(curPath).isDirectory() ? deleteDir(curPath) : fs.unlinkSync(curPath);
    });
    fs.rmdirSync(dirPath);
  }
}

deleteDir('dist');
console.log('Cleaned dist folder');