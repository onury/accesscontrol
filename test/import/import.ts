import { AccessControl } from '../../src/index.js';

console.log(AccessControl);
const ac = new AccessControl();
ac.grant('user').createAny('resource');
console.log(ac.getGrants());
