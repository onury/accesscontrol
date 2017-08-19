#!/usr/bin/env node

const Jasmine = require('jasmine');
const JasmineConsoleReporter = require('jasmine-console-reporter');
const config = {
    reporter: require('./config/reporter.json'),
    jasmine: require('./config/jasmine.json')
};

const jasmine = new Jasmine();
jasmine.loadConfig(config.jasmine);
jasmine.jasmine.DEFAULT_TIMEOUT_INTERVAL = 20000;
jasmine.env.clearReporters();
jasmine.addReporter(new JasmineConsoleReporter(config.reporter));
jasmine.execute();
