/**
 *  Test Suite: public export surface (consumer point of view).
 *
 *  Verifies that everything a consumer needs is reachable from the package
 *  entry — the core class, the error class, the chainable classes, all enums —
 *  and that internal utilities never leak through it. Also pins the enum members
 *  and the package `exports` map (no deep-import of internals).
 *
 *  The `import type` block below additionally documents (and, under a type-check,
 *  enforces) the public *type* surface.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
// Public TYPE surface — if any of these stops being exported from the entry,
// this import fails to type-check (consumer-facing types must stay reachable).
import type {
  AccessControlEventName,
  AccessControlEventPayload,
  AccessEvent,
  AccessReason, // deprecated alias of DenyReason — must stay exported until v4
  BaseEvent,
  ChangeEvent,
  ChangeType,
  ConditionFunction,
  ConditionJSON,
  ConditionLeaf,
  DenyReason,
  ErrorEvent,
  EventListener,
  IAccessControlErrorOptions,
  IAccessControlOptions,
  IAccessInfo,
  IEngine,
  IGrant,
  IGrants,
  IGrantsItem,
  IGrantsList,
  IGrantsListItem,
  IPolicy,
  IQueryInfo,
  IRequirements,
  IResolveOptions,
  IResourceGrants,
  ISetup,
  ISnapshot,
  IStrictOptions,
  OwnerResolver,
  UnknownObject
} from '../src/index.js';
import * as pkg from '../src/index.js';

describe('Public exports: values a consumer imports', () => {
  test('core + chainable + error classes are exported as constructables', () => {
    for (const name of [
      'AccessControl',
      'AccessControlError',
      'Access',
      'Query',
      'Permission',
      'Emitter'
    ] as const) {
      // biome-ignore lint/performance/noDynamicNamespaceImportAccess: iterating the public names is the point of this surface test
      expect(typeof pkg[name], name).toBe('function');
      // biome-ignore lint/performance/noDynamicNamespaceImportAccess: iterating the public names is the point of this surface test
      expect(typeof pkg[name].prototype, name).toBe('object');
    }
  });

  test('all enums are exported with their expected members', () => {
    expect(pkg.Action).toMatchObject({
      CREATE: 'create',
      READ: 'read',
      UPDATE: 'update',
      DELETE: 'delete'
    });
    expect(pkg.Possession).toMatchObject({ OWN: 'own', ANY: 'any' });
    expect(pkg.Charset).toMatchObject({ ASCII: 'ascii', UNICODE: 'unicode' });
    expect(pkg.AccessControlEvent).toMatchObject({
      Access: 'access',
      Change: 'change',
      Error: 'error'
    });
    // ErrorCode: a few representative, machine-readable codes
    expect(pkg.ErrorCode.ROLE_NOT_FOUND).toBe('ROLE_NOT_FOUND');
    expect(pkg.ErrorCode.RESERVED_NAME).toBe('RESERVED_NAME');
    expect(pkg.ErrorCode.LOCKED).toBe('LOCKED');
  });

  test('the entry exports exactly the intended public value surface', () => {
    expect(Object.keys(pkg).sort()).toEqual([
      'Access',
      'AccessControl',
      'AccessControlError',
      'AccessControlEvent',
      'Action',
      'Charset',
      'Emitter',
      'ErrorCode',
      'Permission',
      'Possession',
      'Query'
    ]);
  });

  test('a consumer can build and check entirely through the entry', () => {
    const ac = new pkg.AccessControl(
      {},
      {
        engine: { charset: pkg.Charset.ASCII, safeErrors: true },
        policy: { ownerField: 'ownerId', strict: { roles: true } }
      }
    );
    ac.grant('user').readOwn('post', ['*', '!secret']);
    const perm = ac.can('user', { user: { id: 1 }, post: { ownerId: 1 } }).readOwn('post');
    expect(perm.granted).toBe(true);
    expect(ac.tryCan('ghost').readAny('post').granted).toBe(false);
    const err = (() => {
      try {
        ac.grant('__proto__');
      } catch (e) {
        return e as InstanceType<typeof pkg.AccessControlError>;
      }
      return undefined; // grant() unexpectedly didn't throw
    })();
    expect(err).toBeInstanceOf(pkg.AccessControlError);
    expect(err?.code).toBe(pkg.ErrorCode.RESERVED_NAME);
  });
});

describe('Public exports: internals never leak', () => {
  test('no internal utility / constant is reachable from the entry', () => {
    const leaked = [
      // validation / grants / roles / condition / generic / lock utils
      'normalizeName',
      'normalizeQueryInfo',
      'normalizeAccessInfo',
      'normalizeActionPossession',
      'validName',
      'hasValidNames',
      'compileCondition',
      'evaluateCondition',
      'evaluateConditionAsync',
      'getInspectedGrants',
      'getRoleHierarchyOf',
      'extendRole',
      'commitToGrants',
      'resolveAccess',
      'resolveAccessAsync',
      'eachRole',
      'eachKey',
      'toStringArray',
      'deepFreeze',
      'detail',
      'filter',
      'filterAll',
      'lockAC',
      'preCreateRoles',
      'getActions',
      'getResources',
      // internal constants / arrays
      'NAME_RE',
      'NAME_RE_UNICODE',
      'RESERVED_NAMES',
      'EXTEND_KEY',
      'ERR_LOCK',
      'actions',
      'possessions'
    ];
    const present = leaked.filter((name) => name in pkg);
    expect(present).toEqual([]);
  });

  test('package `exports` map exposes only the entry (no deep imports)', () => {
    const pkgJson = JSON.parse(
      readFileSync(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8')
    );
    expect(Object.keys(pkgJson.exports).sort()).toEqual(['.', './package.json']);
    // the entry resolves to the built ESM + its types
    expect(pkgJson.exports['.']).toMatchObject({
      types: './lib/index.d.ts',
      import: './lib/index.js'
    });
  });
});

// Exercises the imported public types so their import is meaningful (and
// type-checked wherever this file is compiled). Never called.
// biome-ignore lint/suspicious/noExportsInTest: exported only so the unused type-surface probe isn't tree-shaken / flagged unused
export function _publicTypeSurface(
  opts: IAccessControlOptions,
  engine: IEngine,
  policy: IPolicy,
  strict: IStrictOptions,
  query: IQueryInfo,
  access: IAccessInfo,
  grant: IGrant,
  grants: IGrants,
  item: IGrantsItem,
  list: IGrantsList,
  row: IGrantsListItem,
  resGrants: IResourceGrants,
  reqs: IRequirements,
  resolve: IResolveOptions,
  setup: ISetup,
  snap: ISnapshot,
  owner: OwnerResolver,
  cond: ConditionJSON,
  leaf: ConditionLeaf,
  fn: ConditionFunction,
  reason: DenyReason,
  reasonLegacy: AccessReason, // the deprecated alias must remain assignable
  change: ChangeType,
  evName: AccessControlEventName,
  evPayload: AccessControlEventPayload,
  base: BaseEvent,
  access2: AccessEvent,
  change2: ChangeEvent,
  error2: ErrorEvent,
  listener: EventListener,
  errOpts: IAccessControlErrorOptions,
  obj: UnknownObject
): void {
  void [
    opts,
    engine,
    policy,
    strict,
    query,
    access,
    grant,
    grants,
    item,
    list,
    row,
    resGrants,
    reqs,
    resolve,
    setup,
    snap,
    owner,
    cond,
    leaf,
    fn,
    reason,
    reasonLegacy,
    change,
    evName,
    evPayload,
    base,
    access2,
    change2,
    error2,
    listener,
    errOpts,
    obj
  ];
}
