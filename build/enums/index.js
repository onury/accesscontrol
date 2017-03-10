"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var Action_1 = require("./Action");
exports.Action = Action_1.default;
var Possession_1 = require("./Possession");
exports.Possession = Possession_1.default;
var actions = Object.keys(Action_1.default).map(function (k) { return Action_1.default[k]; });
exports.actions = actions;
var possessions = Object.keys(Possession_1.default).map(function (k) { return Possession_1.default[k]; });
exports.possessions = possessions;
//# sourceMappingURL=index.js.map