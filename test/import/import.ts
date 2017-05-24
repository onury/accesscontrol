import { AccessControl } from '../../';

console.log(AccessControl);
let ac = new AccessControl();
ac.grant('user').createAny('resource');
console.log(ac.getGrants());
