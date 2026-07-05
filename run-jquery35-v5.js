"use strict";
const path = require("path");
const engine = require(path.join(__dirname, "jquery35-local-agent-v5.js"));
engine.run(process.argv.slice(2));
