const _ = require('lodash');
function bad(payload) {
  // ruleid: driftguard.js.lodash-defaultsdeep-prototype-pollution
  return _.defaultsDeep({}, payload, { a: 1 });
}
function good(payload) {
  // ok: driftguard.js.lodash-defaultsdeep-prototype-pollution
  return _.defaults({}, payload, { a: 1 });
}
