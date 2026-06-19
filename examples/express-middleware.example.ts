/**
 * Example: AccessControl v3 as Express middleware.
 *
 * Demonstrates a reusable `authorize()` middleware that resolves a permission,
 * enforces ownership via the check context, filters the response by the granted
 * attributes, and wires the `access` event to an audit log.
 *
 * This is reference material (not run by the test suite). Pseudocode is used for
 * the data layer (`db.*`) and auth (`req.user`).
 */

import { AccessControl, type AccessEvent } from 'accesscontrol';

// ---------------------------------------------------------------------------
// 1. Define the policy once, at startup.
// ---------------------------------------------------------------------------

const ac = new AccessControl(
  {},
  {
    policy: {
      // ownership: a record is owned when ctx.user.id === ctx.<resource>.ownerId
      ownerField: 'ownerId',
      // throw on unknown roles/actions/resources to catch typos loudly
      strict: { roles: true, actions: true, resources: true }
    }
  }
);

ac.setup({
  roles: { _: ['user', 'editor', 'admin'] },
  resources: { _: ['article'] },
  actions: ['publish']
});

ac.grant('user').readAny('article', ['*', '!internalNotes']).createOwn('article').updateOwn('article');
ac.grant('editor')
  .extend('user')
  .updateAny('article')
  .where('$.article.status == draft')
  .action('publish', 'article');
ac.grant('admin').extend('editor').deleteAny('article');

// a global gate: only operate in production over a trusted network
ac.require('$.env == prod');

// audit every decision
ac.on('access', (e) => auditLog(e as AccessEvent));

// ---------------------------------------------------------------------------
// 2. A reusable authorization middleware.
// ---------------------------------------------------------------------------

/**
 * Builds middleware for an `action` on a `resource`. The optional `loadRecord`
 * hook fetches the target record so ownership (`own`) and conditions can be
 * evaluated; the loaded record is placed in the check context under the resource
 * name (e.g. `ctx.article`).
 */
function authorize(
  action: string, // e.g. 'read:any', 'update:own', 'publish:own'
  resource: string,
  loadRecord?: (req: any) => Promise<any>
) {
  return async (req: any, res: any, next: any) => {
    try {
      const record = loadRecord ? await loadRecord(req) : undefined;
      const context = {
        env: process.env.NODE_ENV,
        user: req.user, // { id, role }
        [resource]: record // ownership/condition data, keyed by resource name
      };

      const permission = await ac
        .can(req.user.role, context)
        .action(action, resource).grantedAsync;

      if (!permission) return res.status(403).end();

      // stash the permission so the handler can filter its response
      req.permission = ac.can(req.user.role, context).action(action, resource);
      if (record !== undefined) req.record = record;
      next();
    } catch (err) {
      next(err);
    }
  };
}

// ---------------------------------------------------------------------------
// 3. Routes.
// ---------------------------------------------------------------------------

declare const router: any;
declare const db: { findArticle(id: string): Promise<any> };

// read any article — response filtered to the granted attributes
router.get('/articles/:id', authorize('read:any', 'article'), async (req: any, res: any) => {
  const article = await db.findArticle(req.params.id);
  if (!article) return res.status(404).end();
  res.json(req.permission.filter(article)); // strips '!internalNotes', etc.
});

// update only your own article (ownership enforced via the loaded record)
router.patch(
  '/articles/:id',
  authorize('update:own', 'article', (req) => db.findArticle(req.params.id)),
  async (req: any, res: any) => {
    const allowed = req.permission.filter(req.body); // drop disallowed fields
    // await db.updateArticle(req.params.id, allowed);
    res.json(allowed);
  }
);

// custom action gated by a condition (status == draft) and ownership
router.post(
  '/articles/:id/publish',
  authorize('publish:own', 'article', (req) => db.findArticle(req.params.id)),
  async (_req: any, res: any) => {
    // await db.publishArticle(_req.params.id);
    res.status(204).end();
  }
);

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function auditLog(e: AccessEvent): void {
  // e.g. ship to your audit sink; `reason` explains denials
  console.log(
    `[access] ${e.roles.join(',')} ${e.granted ? 'GRANTED' : 'DENIED'} ` +
      `${e.action}:${e.possession ?? ''} ${e.resource}` +
      (e.reason ? ` (${e.reason})` : '')
  );
}
