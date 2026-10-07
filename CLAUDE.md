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

Commit "add whitelisting" on `guilhem/whitelisting` adds:

- A `superuser` boolean on `Users` (model plus migration `20240503220100-add-superuser.js`). A superuser may delete notes owned by others (check in `lib/realtime.js` on the `delete` socket event), and the flag is sent to clients in user presence data.
- `bin/manage_users` options `--adduser <profileid>`, `--deluser <profileid>`, `--superuser <profileid>` and `--list`, which operate by `profileid` rather than email so that OAuth2 users can be pre-provisioned.
- An organization filter for OAuth2 logins. When `oauth2.workspace` (`CMD_OAUTH2_WORKSPACE`, e.g. `Aquila-consortium`) is set, `userProfile` in `lib/web/auth/oauth2/index.js` lists the user's organizations through the Forgejo API (`oauth2.workspaceURL`, default `<baseURL>/api/v1/user/orgs`) and denies the login unless the user is a member. The paging logic is in `lib/web/auth/oauth2/workspace.js` and is tested in `test/oauth2-workspace.js`.

- Logged-in users are rechecked periodically (`oauth2.workspaceRecheckInterval`, default 15 minutes). `passport.deserializeUser` in `lib/web/auth/index.js` calls the checker from `lib/web/auth/oauth2/recheck.js`, which refreshes expired Forgejo access tokens with the stored refresh token. A user who has left the organization loses their session. A Forgejo outage keeps sessions alive.
- Only OAuth2 logins are allowed. `lib/config/index.js` forces every other `is<Provider>Enable` flag to false, and `deserializeUser` drops sessions of users whose stored profile is not from OAuth2.

Note that `passportGeneralCallback` still uses `findOrCreate`, so pre-provisioning with `manage_users` alone does not block unknown users. The organization filter does.

## Conventions

- Code style is eslint with `eslint-config-standard` (no semicolons, 2-space indent, single quotes). Some lines from the fork commit violate this and will fail `yarn run eslint`.
- Commit messages follow Conventional Commits (`fix(scope): ...`, `chore(deps): ...`). Upstream requires a DCO `Signed-off-by` line (see `CONTRIBUTING.md`).
- Developer docs are in `docs/content/dev/` (getting started, webpack, OT, API with `openapi.yml`).
