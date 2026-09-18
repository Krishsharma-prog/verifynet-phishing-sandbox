const { join } = require('path');

/**
 * @type {import("puppeteer").Configuration}
 */
module.exports = {
  // Forces Puppeteer to download Chromium into the project folder 
  // instead of the volatile cloud OS cache.
  cacheDirectory: join(__dirname, '.cache', 'puppeteer'),
};