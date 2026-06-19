import { AccessControlEvent } from './AccessControlEvent.js';
import { Action } from './Action.js';
import { Charset } from './Charset.js';
import { ErrorCode } from './ErrorCode.js';
import { Possession } from './Possession.js';

const actions: string[] = Object.keys(Action).map((k: string) => Action[k]);
const possessions: string[] = Object.keys(Possession).map((k: string) => Possession[k]);

export { AccessControlEvent, Action, actions, Charset, ErrorCode, Possession, possessions };
