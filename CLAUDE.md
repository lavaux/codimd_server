# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

This is a fork of HedgeDoc 1.x (formerly CodiMD), a real-time collaborative Markdown editor. Upstream is `hedgedoc/hedgedoc`. The `guilhem/*` branches carry local changes on top of `master` (see "Local fork changes" below).

## Commands

Package manager is Yarn (Berry, config in `.yarnrc.yml`). Node >= 18; CI tests Node 20, 22 and 24.

- `yarn install`: install dependencies.
- `yarn run build`: production webpack build of the frontend into `public/build/` and the generated `public/views/build/*-pack-*.ejs` templates. The server cannot render pages without these.
- `yarn run dev`: webpack in watch mode for frontend work.
- `node app.js` (or `yarn start`): run the server. Needs a `config.json` (copy `config.json.example`) or `CMD_*` environment variables. For live reload: `nodemon --watch app.js --watch lib --watch locales app.js`.
- `yarn test`: runs eslint, jsonlint (requires `jq`) and the mocha suite.
- `yarn run eslint`: lint `lib`, `public`, `test` and `app.js` with zero warnings allowed.
- `yarn run mocha-suite`: mocha tests in `test/` against an in-memory SQLite DB.
- Single test file or test case:
  `NODE_ENV=test CMD_DB_URL="sqlite::memory:" npx mocha --exit test/note.js -g 'extractMeta'`
- `yarn run markdownlint`: remark lint over Markdown docs.

## Architecture

### Backend (`app.js`, `lib/`)

- `app.js` wires everything: Express app, Helmet/CSP, sessions stored in the DB via `connect-session-sequelize`, passport, i18n, Socket.IO, and the routers from `lib/web/`. At startup it runs DB migrations before listening.
- Configuration (`lib/config/index.js`) is built by deep-merging, in order: `default.js`, `defaultSSL.js`, `oldDefault.js`, debug/package info, the `config.json` section for the current `NODE_ENV`, then legacy env vars (`oldEnvironment.js`, `hackmdEnvironment.js`), current `CMD_*` env vars (`environment.js`), and Docker secrets. Later sources win. A new option normally needs an entry in `default.js` and `environment.js`, plus documentation in `docs/content/configuration.md`. The resulting config is deep-frozen.
- Models (`lib/models/`) use Sequelize v5 with `sequelize.import`. Every file in that directory except `index.js` is auto-loaded as a model. Schema changes require a migration in `lib/migrations/` (timestamped filename, old-style `up(queryInterface, Sequelize)` / `down` signature), which Umzug applies automatically on boot. Supported DBs: SQLite, Postgres, MySQL/MariaDB.
- `lib/realtime.js` is the collaboration core. It holds in-memory state for active notes and connected users, authenticates sockets through `passport.socketio`, and periodically flushes notes to the DB. Concurrent editing uses operational transformation from `lib/ot/` (a port of ot.js; see `docs/content/dev/ot.md`). Diff/patch work for revisions runs in a child process (`lib/workers/dmpWorker.js`).
- `lib/web/` contains the HTTP routers: `note/` (note views, publish, slides, actions such as download/revision), `auth/` (one subdirectory per passport strategy, all funnelling into `auth/utils.js#passportGeneralCallback`, which does `User.findOrCreate` by `profileid`), `imageRouter/` (one module per upload backend, selected by `config.imageUploadType`), `historyRouter`, `userRouter`, `statusRouter`, and `middleware/`.
- Permission logic for notes (freely, editable, limited, locked, protected, private) is in `lib/config/enum.js` and enforced both in the note routers and in `realtime.js`.

### Frontend (`public/`)

- Plain JS (jQuery, CodeMirror 5, Bootstrap 3) bundled by webpack. `webpack.common.js` defines the entry points (index/editor, cover, pretty, slide) and uses `HtmlWebpackPlugin` to emit the `public/views/build/*.ejs` include files that the EJS views in `public/views/` pull in.
- `public/js/index.js` is the editor client: Socket.IO connection, OT client (`public/vendor/ot/`), and UI. `public/js/extra.js` and `render.js` do Markdown rendering and sanitization (markdown-it plus many plugins, then an XSS whitelist filter).
- Translations live in `locales/*.json`; the supported list is `locales/_supported.json`.

### CLI tools (`bin/`)

- `bin/manage_users`: create, delete and reset users in the DB directly (uses the same models and config as the server).
- `bin/cleanup`, `bin/migrate_from_fs_to_minio`, `bin/setup`, `bin/heroku`.

## Local fork changes

The `guilhem/whitelisting` branch adds:

- **Organization filter.** When `oauth2.workspace` (`CMD_OAUTH2_WORKSPACE`, e.g. `Aquila-consortium`) is set, `userProfile` in `lib/web/auth/oauth2/index.js` lists the user's organizations through the Forgejo API (`oauth2.workspaceURL`, default `<baseURL>/api/v1/user/orgs`) and denies the login unless the user is a member. Paging is in `lib/web/auth/oauth2/workspace.js`.
- **OAuth2 only.** `lib/config/index.js` forces every other `is<Provider>Enable` flag to false, and `deserializeUser` in `lib/web/auth/index.js` drops sessions of users whose stored profile is not from OAuth2.
- **Periodic recheck.** `deserializeUser` calls the checker from `lib/web/auth/oauth2/recheck.js` at the first request after login and then every `oauth2.workspaceRecheckInterval` ms (default 15 minutes). It renews expired Forgejo access tokens with the stored refresh token, ends the session of a user who left the organization, and keeps sessions during a Forgejo outage.
- **Superusers, decided by aquila-website.** The recheck also calls `refreshPrivileges` from `lib/web/auth/oauth2/aquila.js`, which asks aquila-website (`aquila.superuserURL` with Bearer `aquila.token`; endpoint `members.superuser_status` in `~/PROJECTS/aquila/aquila_website`) and caches the answer in `Users.superuser`. If aquila-website is unreachable the cached value is kept. Nothing else sets the flag. Use `isSuperuser(user)` from `lib/utils.js` for checks.
- **Superuser powers.** Read private notes (both `checkViewPermission` functions), edit locked/protected/private notes (`ifMayEdit`), change any note's permission and owner, delete notes. Note changes go through `setNotePermission` and `setNoteOwner` in `lib/realtime.js`, which update the DB and any open editors. They are used by the socket events `permission`/`owner` and by `lib/web/adminRouter.js` (`/admin`, `/admin/users`, `POST /admin/notes/:noteId/{permission,owner}` with JSON bodies only).
- **UI.** Elements with class `ui-superuser-only` (red "superuser" label, Admin links, "Change owner" entry) are shown by `updateSuperuserUI()` in `public/js/index.js` and by `public/js/cover.js` from `/me`.
- **Note listing API.** `GET /api/notes` (`lib/web/apiRouter.js`) returns every note as JSON (id, url, title, tags, permission, owner's Forgejo login, dates). It requires `Authorization: Bearer <aquila.token>`, answers 404 when no token is configured, and is excluded from the session middleware in `app.js`. Tags are parsed from the content with `Note.parseNoteInfo` at each request. `PATCH /api/notes/:noteId` (note `id` or `url`) takes a JSON body with any of `permission`, `owner` (Forgejo login) and `url` (alias, `null` to remove it) and returns the updated entry. It goes through `setNotePermission`, `setNoteOwner` and `setNoteAlias` in `lib/realtime.js`. `setNoteAlias` sends a `moved` socket event so open editors reload at the new URL.
- **`bin/manage_users`** options `--adduser <profileid>`, `--deluser <profileid>` and `--list` operate by `profileid` rather than email.

Note that `passportGeneralCallback` still uses `findOrCreate`, so pre-provisioning with `manage_users` alone does not block unknown users. The organization filter does.

## Conventions

- Code style is eslint with `eslint-config-standard` (no semicolons, 2-space indent, single quotes). `bin/` is not linted.
- Commit messages follow Conventional Commits (`fix(scope): ...`, `chore(deps): ...`). Upstream requires a DCO `Signed-off-by` line (see `CONTRIBUTING.md`).
- Developer docs are in `docs/content/dev/` (getting started, webpack, OT, API with `openapi.yml`).
