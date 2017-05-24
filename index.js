var AC = require('./lib').AccessControl;
module.exports = AC;
// adding circular ref to allow easy importing in both ES5/6 and TS projects
module.exports.AccessControl = AC;
