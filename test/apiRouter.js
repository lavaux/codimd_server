'use strict'

const assert = require('assert')
const fs = require('fs')
const path = require('path')

const models = require('../lib/models')
const realtime = require('../lib/realtime')
const { createTokenCheck, noteToEntry, parseChanges, findUserByLogin } = require('../lib/web/apiRouter')

function fakeReq (authorization) {
  return {
    get (name) {
      return name.toLowerCase() === 'authorization' ? authorization : undefined
    }
  }
}

function fakeRes () {
  return {
    statusCode: 200,
    body: undefined,
    status (code) {
      this.statusCode = code
      return this
    },
    json (body) {
      this.body = body
      return this
    }
  }
}

// runs the middleware and tells whether it let the request through
function run (check, authorization) {
  const res = fakeRes()
  let passed = false
  check(fakeReq(authorization), res, () => { passed = true })
  return { passed, res }
}

describe('api token check', function () {
  it('hides the endpoint when no token is configured', function () {
    const { passed, res } = run(createTokenCheck(undefined), 'Bearer anything')
    assert.strictEqual(passed, false)
    assert.strictEqual(res.statusCode, 404)
  })

  it('rejects a request without Authorization header', function () {
    const { passed, res } = run(createTokenCheck('s3cret'), undefined)
    assert.strictEqual(passed, false)
    assert.strictEqual(res.statusCode, 401)
  })

  it('rejects a wrong token', function () {
    const { passed, res } = run(createTokenCheck('s3cret'), 'Bearer s3cre')
    assert.strictEqual(passed, false)
    assert.strictEqual(res.statusCode, 401)
  })

  it('rejects the right token without the Bearer scheme', function () {
    const { passed } = run(createTokenCheck('s3cret'), 's3cret')
    assert.strictEqual(passed, false)
  })

  it('accepts the right token', function () {
    const { passed } = run(createTokenCheck('s3cret'), 'Bearer s3cret')
    assert.strictEqual(passed, true)
  })

  it('accepts the scheme name in any case', function () {
    const { passed } = run(createTokenCheck('s3cret'), 'bearer s3cret')
    assert.strictEqual(passed, true)
  })
})

describe('api noteToEntry', function () {
  const lastchangeAt = new Date('2026-10-06T15:12:00Z')
  const createdAt = new Date('2026-10-01T09:00:00Z')

  it('reports title, tags and the Forgejo login of the owner', function () {
    const entry = noteToEntry({
      id: '11111111-2222-3333-4444-555555555555',
      alias: 'meeting',
      title: 'Meeting',
      content: '---\ntags: a, b\n---\n# Meeting',
      permission: 'editable',
      owner: { id: 'u1', profile: JSON.stringify({ username: 'jdoe', provider: 'oauth2' }) },
      createdAt,
      lastchangeAt
    })
    assert.deepStrictEqual(entry, {
      id: '11111111-2222-3333-4444-555555555555',
      url: 'meeting',
      title: 'Meeting',
      tags: ['a', 'b'],
      permission: 'editable',
      owner: 'jdoe',
      createdAt,
      lastchangeAt
    })
  })

  it('reads tags from a "tags:" line and handles notes without owner', function () {
    const entry = noteToEntry({
      id: '11111111-2222-3333-4444-555555555555',
      alias: null,
      title: '',
      content: '# Hello\n###### tags: `x` `y`',
      permission: 'freely',
      owner: null,
      createdAt,
      lastchangeAt
    })
    assert.strictEqual(entry.owner, null)
    assert.strictEqual(entry.title, 'Untitled')
    assert.deepStrictEqual(entry.tags, ['x', 'y'])
    assert.ok(entry.url && entry.url !== 'null')
  })
})

describe('api parseChanges', function () {
  function rejects (body, status, pattern) {
    assert.throws(() => parseChanges(body), err => err.status === status && pattern.test(err.message))
  }

  it('accepts permission, owner and url together', function () {
    const body = { permission: 'private', owner: 'jdoe', url: 'meeting' }
    assert.deepStrictEqual(parseChanges(body), body)
  })

  it('accepts a null url, which removes the alias', function () {
    assert.deepStrictEqual(parseChanges({ url: null }), { url: null })
  })

  it('rejects a missing, empty or non-object body', function () {
    rejects(undefined, 400, /JSON object/)
    rejects([], 400, /JSON object/)
    rejects({}, 400, /nothing to change/)
  })

  it('rejects unknown fields', function () {
    rejects({ title: 'x' }, 400, /unknown field: title/)
  })

  it('rejects an invalid permission', function () {
    rejects({ permission: 'public' }, 400, /invalid permission/)
  })

  it('rejects an owner that is not a login', function () {
    rejects({ owner: '' }, 400, /Forgejo login/)
    rejects({ owner: 42 }, 400, /Forgejo login/)
  })

  it('rejects a url that is neither a string nor null', function () {
    rejects({ url: 42 }, 400, /string or null/)
  })
})

// first path segments of the routes declared in lib/web and app.js
function routeSegments () {
  const files = ['app.js']
  const walk = function (dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const file = path.join(dir, entry.name)
      if (entry.isDirectory()) walk(file)
      else if (file.endsWith('.js')) files.push(file)
    }
  }
  walk('lib/web')
  const segments = new Set()
  const routePattern = /\.(?:get|post|put|patch|delete|all|use)\(\s*['"]\/([^'"/:?]+)/g
  for (const file of files) {
    for (const match of fs.readFileSync(file, 'utf8').matchAll(routePattern)) {
      segments.add(match[1])
    }
  }
  return segments
}

describe('api note url checks', function () {
  before(function () {
    return models.sequelize.sync({ force: true })
  })

  it('reserves every first path segment that a route uses', function () {
    for (const segment of routeSegments()) {
      assert.ok(realtime.reservedNoteURLs.includes(segment.toLowerCase()), `route /${segment} is not reserved`)
    }
  })

  it('refuses a route name or a public file as url, in any case', async function () {
    for (const url of ['admin', 'Admin', 'new', 'css', 'default.md']) {
      await assert.rejects(realtime.setNoteAlias('00000000-0000-4000-8000-000000000000', url),
        err => err.status === 400 && /not allowed/.test(err.message), url)
    }
  })

  it('looks a note up by id, alias, encoded id and shortid', async function () {
    const note = await models.Note.create({ content: '# x', alias: 'lookup-test' })
    for (const key of [note.id, 'lookup-test', models.Note.encodeNoteId(note.id), note.shortid]) {
      assert.strictEqual(await realtime.findNoteId(key), note.id, key)
    }
  })

  it('does not create a note for a docs file without note', async function () {
    const count = await models.Note.count()
    assert.strictEqual(await realtime.findNoteId('features'), null)
    assert.strictEqual(await models.Note.count(), count)
  })
})

describe('api findUserByLogin', function () {
  before(async function () {
    await models.sequelize.sync({ force: true })
    await models.User.create({ profileid: 'none', profile: null })
    await models.User.create({ profileid: 'p1', profile: JSON.stringify({ username: 'Alice', provider: 'oauth2' }) })
  })

  it('matches the login regardless of case', async function () {
    const user = await findUserByLogin('alice')
    assert.strictEqual(user.profile.includes('Alice'), true)
  })

  it('does not match users without login against "null"', async function () {
    await assert.rejects(findUserByLogin('null'), err => err.status === 404)
  })
})
