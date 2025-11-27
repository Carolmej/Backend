import fs from 'fs';

const folders = ['./reports', './projects'];

folders.forEach(folder => {
    if (!fs.existsSync(folder)) {
      fs.mkdirSync(folder, { recursive: true });
    }
});