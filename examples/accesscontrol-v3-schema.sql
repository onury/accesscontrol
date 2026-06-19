-- ============================================================================
-- AccessControl v3 — PostgreSQL schema (relational / queryable storage)
-- ----------------------------------------------------------------------------
-- Two storage strategies are supported:
--   A) Single JSONB blob  : store `ac.getGrants()` in one JSONB column and
--                           rehydrate with `new AccessControl(jsonb)`. Simplest.
--   B) Relational rows     : the tables below. Use `ac.getGrantsList()` and
--                           `ac.getRequirements()` to dump rows, and feed the
--                           rows back via the constructor / setGrants().
-- This file shows strategy B. Everything is JSON-serializable either way.
--
-- WHERE EACH CONCEPT LIVES:
--   conditions   -> ac_grants.condition (JSONB), per rule.
--   groups/cats  -> NOT separate columns. They are `/`-qualified NAMES in
--                   ac_grants.role / ac_grants.resource ('staff/editor',
--                   'content/post'); membership is recorded in ac_roles.group
--                   / ac_resources.category (the setup() vocabulary).
--   requirements -> ac_requirements (its own table); NOT part of grants.
-- ============================================================================

-- --- Vocabulary (setup()): required for strict.*; also records group/category ---

-- Roles. `name` is the canonical (possibly '/'-qualified) id; `group` is parsed.
CREATE TABLE ac_roles (
  name    TEXT PRIMARY KEY,        -- 'user' or 'staff/editor'  (case-preserving, [A-Za-z0-9_-], '/' sep)
  "group" TEXT                     -- nullable; e.g. 'staff'
);

-- Resources, with optional category.
CREATE TABLE ac_resources (
  name     TEXT PRIMARY KEY,       -- 'media' or 'content/post'
  category TEXT                    -- nullable; e.g. 'content'
);

-- Action vocabulary (CRUD + custom: 'publish', 'approve', ...).
CREATE TABLE ac_actions (
  name TEXT PRIMARY KEY
);

-- --- Role inheritance ($extend) — the §3 fix: relational/list form supports this ---
CREATE TABLE ac_role_inheritance (
  role    TEXT NOT NULL REFERENCES ac_roles(name) ON DELETE CASCADE,
  extends TEXT NOT NULL REFERENCES ac_roles(name) ON DELETE CASCADE,
  PRIMARY KEY (role, extends)
);

-- --- Grant rules — the heart. One row per IGrant. -----------------------------
-- Option B (multiple rules per action) => NOT unique on (role,resource,action);
-- a role may hold several conditional rules for the same action.
-- A group-level grant simply has role = the group name (e.g. 'staff').
CREATE TABLE ac_grants (
  id         BIGSERIAL PRIMARY KEY,
  role       TEXT NOT NULL,                 -- 'editor', 'staff/editor', or group 'staff'
  resource   TEXT NOT NULL,                 -- 'post' or 'content/post'
  action     TEXT NOT NULL,                 -- 'create','update','publish',...
  possession TEXT CHECK (possession IN ('own','any')),    -- NULL => 'any'
  effect     TEXT NOT NULL DEFAULT 'grant'
             CHECK (effect IN ('grant','deny')),          -- deny-overrides (§5.6)
  attributes JSONB NOT NULL DEFAULT '["*"]'::jsonb,       -- glob notation array
  condition  JSONB                                        -- NULL => unconditional
);
CREATE INDEX ix_ac_grants_lookup ON ac_grants (role, resource, action);

-- --- Requirements — require() gates (§7.2). Mandatory; can only restrict. -----
CREATE TABLE ac_requirements (
  id        BIGSERIAL PRIMARY KEY,
  scope     TEXT NOT NULL CHECK (scope IN ('global','category','resource')),
  target    TEXT,                            -- category/resource name; NULL if global
  condition JSONB NOT NULL
);

-- ============================================================================
-- Seed (representative subset — full set mirrors accesscontrol-v3-grants.example.ts)
-- ============================================================================

INSERT INTO ac_roles (name, "group") VALUES
  ('admin', NULL), ('editor', NULL), ('moderator', NULL),
  ('author', NULL), ('user', NULL);

INSERT INTO ac_resources (name, category) VALUES
  ('post', NULL), ('comment', NULL), ('media', NULL), ('profile', NULL);

INSERT INTO ac_role_inheritance (role, extends) VALUES
  ('admin', 'editor'), ('editor', 'author'),
  ('moderator', 'author'), ('author', 'user');

-- plain grant (any), with a negated attribute
INSERT INTO ac_grants (role, resource, action, possession, effect, attributes, condition) VALUES
  ('user', 'post', 'read', 'any', 'grant', '["*","!authorId"]', NULL),
  -- ownership-gated grant
  ('author', 'post', 'create', 'own', 'grant', '["*","!authorId","!status"]', NULL),
  -- conditional grant: authors may publish only their OWN drafts
  ('author', 'post', 'publish', 'own', 'grant', '["*"]',
     '["$.post.status","==","draft"]'),
  -- conditional grant: comment on a post only if it is not locked
  ('user', 'comment', 'create', 'own', 'grant', '["*"]',
     '["$.post.locked","==",false]'),
  -- DENY (deny-overrides): moderator inherits author's publish but is denied it
  ('moderator', 'post', 'publish', 'own', 'deny', '["*"]', NULL);

-- group/category example: a GROUP-level grant (role = 'staff') on a categorized resource
-- (requires the vocabulary rows for 'staff'/'content' to exist when strict is on)
-- INSERT INTO ac_grants (role, resource, action, possession, attributes)
--   VALUES ('staff', 'content/post', 'read', 'any', '["*"]');

-- require() gates
INSERT INTO ac_requirements (scope, target, condition) VALUES
  ('resource', 'profile', '["$.ip","in",["10.0.0.0/8"]]'),
  ('resource', 'media',   '["$.now.weekday","in",["mon","tue","wed","thu","fri"]]');
