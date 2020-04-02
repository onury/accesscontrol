'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
var Action_1 = require('./Action');
exports.Action = Action_1.Action;
var Possession_1 = require('./Possession');
exports.Possession = Possession_1.Possession;
var actions = Object.keys(Action_1.Action).map(function (k) {
    return Action_1.Action[k];
});
exports.actions = actions;
var possessions = Object.keys(Possession_1.Possession).map(function (k) {
    return Possession_1.Possession[k];
});
exports.possessions = possessions;
