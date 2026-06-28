---
title: NestJS Integration
description: The official nestjs-accesscontrol package — fluent CRUD decorators, a fail-closed guard, forRootAsync for DB-driven grants, and attribute filtering on the way out.
---

[**nestjs-accesscontrol**](https://github.com/onury/nestjs-accesscontrol) is the
**official** NestJS integration for AccessControl v3 — from the same author. It
speaks accesscontrol's own vocabulary (roles, `action`, possession `own`/`any`,
the `Permission` object) and builds on the v3 API (`tryCan`,
`Permission.filter()`, declarative conditions) rather than wrapping it in a new
one. Your auth layer is left entirely to you.

:::note[ESM-only, like v3]
Requires Node ≥ 20 and NestJS 10/11. Still on AccessControl **v2**?
[`nest-access-control`](https://github.com/nestjsx/nest-access-control) remains
the right choice.
:::

## Install

```bash
npm install nestjs-accesscontrol accesscontrol
```

`@nestjs/common`, `@nestjs/core`, `reflect-metadata`, and `rxjs` are peer
dependencies (already present in any Nest app).

## Define grants

Use the same fluent accesscontrol API you already know:

```ts
import { AccessControl } from 'accesscontrol';

export const ac = new AccessControl();
ac.grant('user')
  .readAny('article', ['*', '!authorEmail']) // can't see authorEmail
  .createOwn('article')
  .updateOwn('article')
  .deleteOwn('article');
ac.grant('admin').extend('user').updateAny('article').deleteAny('article');
ac.lock();
```

## Register the module

Your auth guard runs **first** and sets `request.user`; the access-control guard
then reads `request.user.role`.

```ts
import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AccessControlModule, AccessControlGuard } from 'nestjs-accesscontrol';
import { ac } from './grants';
import { JwtAuthGuard } from './auth/jwt-auth.guard';

@Module({
  imports: [AccessControlModule.forRoot({ ac })],
  providers: [
    { provide: APP_GUARD, useClass: JwtAuthGuard },        // authenticate first…
    { provide: APP_GUARD, useClass: AccessControlGuard }   // …then authorize.
  ]
})
export class AppModule {}
```

:::caution[Guard order matters]
`AccessControlGuard` expects `request.user` to already be populated. Register
your auth guard before it (or compose per route with
`@UseGuards(JwtAuthGuard, AccessControlGuard)`).
:::

## Declare access on routes

The eight fluent decorators map 1:1 onto accesscontrol's methods. On a granted
request the resolved `Permission` is attached to `request.permission`, so the
handler can filter its response down to the visible attributes.

```ts
import { Controller, Get, Patch, Param, Body, Req } from '@nestjs/common';
import { ReadAny, UpdateOwn, FilterResponse, assertOwner } from 'nestjs-accesscontrol';
import type { AccessControlRequest } from 'nestjs-accesscontrol';

@Controller('articles')
export class ArticlesController {
  @ReadAny('article')
  @FilterResponse() // strips attributes the role may not see (e.g. authorEmail)
  @Get()
  findAll() {
    return this.articles.findAll();
  }

  @UpdateOwn('article')
  @Patch(':id')
  async update(@Param('id') id: string, @Body() dto: UpdateDto, @Req() req: AccessControlRequest) {
    const article = await this.articles.find(id);
    // `own` enforcement needs your data — compare the owner yourself:
    assertOwner(req.user?.id, article.authorId);
    return req.permission!.filter(await this.articles.update(id, dto));
  }
}
```

There are three decorator forms, all combining with **AND** (every rule on a
route must pass):

| Form | Example | Use |
| --- | --- | --- |
| **Fluent CRUD** | `@ReadAny('article')`, `@UpdateOwn('article')` | the everyday surface |
| **Generic** | `@Can('publish', 'article', 'own')` | custom (non-CRUD) actions |
| **Canonical** | `@RequirePermission(rule \| rule[])` | multi-rule / dynamic routes |

## DB-driven grants

Load grants from a database with `forRootAsync` — the factory may return a built
`AccessControl` or a grants object/list (which the module locks for you):

```ts
AccessControlModule.forRootAsync({
  imports: [PrismaModule],
  inject: [PrismaService],
  useFactory: async (prisma: PrismaService) => {
    const rows = await prisma.grant.findMany();
    return new AccessControl(rows).lock();
  }
});
```

## Filtering & ownership

The guard authorizes the _grant_ ("may this role update its own articles?"), but
only your code knows who owns a given record. A few helpers cover the rest:

```ts
import { filterByPermission, assertOwner } from 'nestjs-accesscontrol';

// Strip attributes the role may not see — in a service, without a request:
const visible = filterByPermission(permission, article);

// Enforce `own` — throws ForbiddenException on mismatch:
assertOwner(req.user.id, article.authorId);
```

To query grants anywhere, inject the shared instance with `@InjectAccessControl()`:

```ts
import { InjectAccessControl } from 'nestjs-accesscontrol';
import { AccessControl } from 'accesscontrol';

constructor(@InjectAccessControl() private readonly ac: AccessControl) {}

canPromote(role: string) {
  return this.ac.tryCan(role).updateAny('user').granted;
}
```

The full API — every decorator, the interceptor, configuration options
(`getRole`, `isGlobal`) and exported types — is documented in the
[package README](https://github.com/onury/nestjs-accesscontrol#readme).
