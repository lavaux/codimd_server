'use strict'

const assert = require('assert')

const models = require('../lib/models')
const realtime = require('../lib/realtime')
const ot = require('../lib/ot')
const api = require('../lib/web/apiV1Router')

function fakeReq (user, { params = {}, query = {}, body, headers = {}, accept = 'application/json' } = {}) {
  return {
    apiUser: user,
    params,
    query,
    body,
    get: name => headers[name],
    accepts: types => types.includes(accept) ? accept : false
  }
}

function fakeRes () {
  return {
    statusCode: 200,
    headers: {},
    body: undefined,
    set (name, value) { this.headers[name] = value; return this },
    status (code) { this.statusCode = code; return this },
    json (body) { this.body = body; return this },
    type (value) { this.headers['Content-Type'] = value; return this },
    send (body) { this.body = body; return this },
    end () { return this }
  }
}

// calls a handler and returns the response, or the status error it threw
async function call (handler, req) {
  const res = fakeRes()
  try {
    await handler(req, res)
  } catch (err) {
    if (!err.status) throw err
    res.statusCode = err.status
    res.body = { error: err.message }
  }
  return res
}

const profile = login => JSON.stringify({ username: login, provider: 'oauth2' })

describe('api v1', function () {
  let alice, bob, admin, emitted

  beforeEach(async function () {
    await models.sequelize.sync({ force: true })
    alice = await models.User.create({ profileid: 'a', profile: profile('alice') })
    bob = await models.User.create({ profileid: 'b', profile: profile('bob') })
    admin = await models.User.create({ profileid: 'c', profile: profile('admin'), superuser: true })
    emitted = []
    realtime.io = { to: room => ({ emit: (...args) => emitted.push([room, ...args]) }) }
  })

  afterEach(function () {
    Object.keys(realtime.notes).forEach(id => delete realtime.notes[id])
  })

  describe('listing', function () {
    it('lists owned notes and viewable notes of the history', async function () {
      const own = await models.Note.create({ ownerId: alice.id, content: '# mine', title: 'mine' })
      const shared = await models.Note.create({ ownerId: bob.id, content: '# shared', permission: 'editable', alias: 'shared-note' })
      const hidden = await models.Note.create({ ownerId: bob.id, content: '# secret', permission: 'private' })
      await models.Note.create({ ownerId: bob.id, content: '# elsewhere', permission: 'editable' })
      const history = [shared.alias, models.Note.encodeNoteId(hidden.id)].map(id => ({ id, text: '', time: 0, tags: [] }))
      await alice.update({ history: JSON.stringify(history) })
      const res = await call(api.listNotes, fakeReq(alice))
      assert.deepStrictEqual(res.body.map(entry => entry.id).sort(), [own.id, shared.id].sort())
      assert.ok(!('content' in res.body[0]))
    })
  })

  describe('create and read', function () {
    it('creates a note owned by the user, without carriage returns', async function () {
      const res = await call(api.createNote, fakeReq(alice, { body: '# Title\r\nbody' }))
      assert.strictEqual(res.statusCode, 201)
      const note = await models.Note.findByPk(res.body.id)
      assert.strictEqual(note.ownerId, alice.id)
      assert.strictEqual(note.content, '# Title\nbody')
      assert.strictEqual(note.title, 'Title')
      assert.ok(res.headers.Location.endsWith('/api/v1/notes/' + res.body.url))
    })

    it('refuses a body that is not text', async function () {
      const res = await call(api.createNote, fakeReq(alice, { body: {} }))
      assert.strictEqual(res.statusCode, 415)
    })

    it('refuses an alias when free URLs are disabled, without creating a note', async function () {
      const count = await models.Note.count()
      const res = await call(api.createNote, fakeReq(alice, { body: 'x', query: { url: 'my-alias' } }))
      assert.strictEqual(res.statusCode, 403)
      assert.strictEqual(await models.Note.count(), count)
    })

    it('checks that an alias is free before creating the note', async function () {
      await models.Note.create({ ownerId: bob.id, content: '', alias: 'taken' })
      await assert.rejects(realtime.checkNoteAlias('taken'), err => err.status === 409)
      await realtime.checkNoteAlias('free-alias')
    })

    it('returns the content with an ETag, or the raw Markdown', async function () {
      const note = await models.Note.create({ ownerId: alice.id, content: 'hello', permission: 'private' })
      const res = await call(api.getNote, fakeReq(alice, { params: { noteId: note.id } }))
      assert.strictEqual(res.body.content, 'hello')
      assert.strictEqual(res.headers.ETag, realtime.contentETag('hello'))
      const raw = await call(api.getNote, fakeReq(alice, { params: { noteId: note.id }, accept: 'text/markdown' }))
      assert.strictEqual(raw.body, 'hello')
    })

    it('hides a private note of someone else, but not from a superuser', async function () {
      const note = await models.Note.create({ ownerId: alice.id, content: 'secret', permission: 'private' })
      assert.strictEqual((await call(api.getNote, fakeReq(bob, { params: { noteId: note.id } }))).statusCode, 404)
      assert.strictEqual((await call(api.getNote, fakeReq(admin, { params: { noteId: note.id } }))).body.content, 'secret')
    })
  })

  describe('content changes', function () {
    let note

    beforeEach(async function () {
      note = await models.Note.create({ ownerId: alice.id, content: 'one\n', permission: 'locked' })
    })

    function put (user, body, ifMatch) {
      const headers = ifMatch ? { 'If-Match': ifMatch } : {}
      return call(api.replaceContent, fakeReq(user, { params: { noteId: note.id }, body, headers }))
    }

    it('requires If-Match', async function () {
      assert.strictEqual((await put(alice, 'two')).statusCode, 428)
    })

    it('refuses a stale ETag and accepts the current one', async function () {
      assert.strictEqual((await put(alice, 'two', realtime.contentETag('other'))).statusCode, 412)
      const res = await put(alice, 'two\n', 'W/' + realtime.contentETag('one\n'))
      assert.strictEqual(res.statusCode, 204)
      assert.strictEqual(res.headers.ETag, realtime.contentETag('two\n'))
      const stored = await models.Note.findByPk(note.id)
      assert.strictEqual(stored.content, 'two\n')
      assert.strictEqual(stored.lastchangeuserId, alice.id)
    })

    it('forbids a member to edit a locked note of someone else', async function () {
      assert.strictEqual((await put(bob, 'two', '*')).statusCode, 403)
    })

    it('appends on a new line', async function () {
      await models.Note.update({ content: 'one' }, { where: { id: note.id } })
      const res = await call(api.appendContent, fakeReq(alice, { params: { noteId: note.id }, body: 'two' }))
      assert.strictEqual(res.statusCode, 204)
      assert.strictEqual((await models.Note.findByPk(note.id)).content, 'one\ntwo')
    })
  })

  describe('open notes', function () {
    function openNote (note, content) {
      realtime.notes[note.id] = {
        id: note.id,
        owner: note.ownerId,
        permission: note.permission,
        server: new ot.EditorSocketIOServer(content, [], note.id, () => {}, () => {}),
        socks: [],
        users: {},
        tempUsers: {},
        authorship: []
      }
      return realtime.notes[note.id]
    }

    it('sends the change to the editors as one operation', async function () {
      const note = await models.Note.create({ ownerId: alice.id, content: 'stale' })
      const open = openNote(note, 'hello world')
      const res = await call(api.replaceContent, fakeReq(alice, {
        params: { noteId: note.id }, body: 'hello there world', headers: { 'If-Match': realtime.contentETag('hello world') }
      }))
      assert.strictEqual(res.statusCode, 204)
      assert.strictEqual(open.server.document, 'hello there world')
      assert.strictEqual(open.server.operations.length, 1)
      assert.strictEqual(open.server.isDirty, true)
      assert.strictEqual(open.lastchangeuser, alice.id)
      assert.notDeepStrictEqual(open.authorship, [])
      assert.deepStrictEqual(emitted.map(event => event[1]), ['operation', 'client_left'])
      assert.deepStrictEqual(emitted[0].slice(2, 5), ['api', 1, [6, 'there ', 5]])
      // the DB is written by the next flush, not by the API
      assert.strictEqual((await models.Note.findByPk(note.id)).content, 'stale')
    })

    it('takes the closed-note path when a teardown held the lock', async function () {
      const note = await models.Note.create({ ownerId: alice.id, content: 'one' })
      const open = openNote(note, 'one')
      const teardown = realtime.withNoteLock(note.id, () => new Promise(resolve => setTimeout(() => {
        delete realtime.notes[note.id]
        resolve()
      }, 20)))
      const write = realtime.writeNoteContent(note.id, content => content + ' two', alice.id)
      await teardown
      await write
      assert.strictEqual(open.server.document, 'one')
      assert.strictEqual((await models.Note.findByPk(note.id)).content, 'one two')
    })

    it('waits for a load holding the lock, then writes into the open note', async function () {
      const note = await models.Note.create({ ownerId: alice.id, content: 'one' })
      let open
      const load = realtime.withNoteLock(note.id, () => new Promise(resolve => setTimeout(() => {
        open = openNote(note, 'one')
        resolve()
      }, 20)))
      const write = realtime.writeNoteContent(note.id, content => content + ' two', alice.id)
      await load
      await write
      assert.strictEqual(open.server.document, 'one two')
      assert.strictEqual((await models.Note.findByPk(note.id)).content, 'one')
    })

    it('runs queued tasks of one note in order', async function () {
      const order = []
      await Promise.all([
        realtime.withNoteLock('n', () => new Promise(resolve => setTimeout(() => { order.push(1); resolve() }, 20))),
        realtime.withNoteLock('n', () => { order.push(2) }),
        realtime.withNoteLock('n', () => Promise.reject(new Error('x'))).catch(() => order.push(3)),
        realtime.withNoteLock('n', () => { order.push(4) })
      ])
      assert.deepStrictEqual(order, [1, 2, 3, 4])
    })
  })

  describe('manage and delete', function () {
    let note

    beforeEach(async function () {
      note = await models.Note.create({ ownerId: alice.id, content: 'x', permission: 'editable' })
    })

    function patch (user, body) {
      return call(api.patchNote, fakeReq(user, { params: { noteId: note.id }, body }))
    }

    it('lets the owner change the permission', async function () {
      const res = await patch(alice, { permission: 'private' })
      assert.strictEqual(res.body.permission, 'private')
    })

    it('forbids others and refuses unknown fields', async function () {
      assert.strictEqual((await patch(bob, { permission: 'private' })).statusCode, 403)
      assert.strictEqual((await patch(alice, { owner: 'bob' })).statusCode, 400)
    })

    it('lets only the owner or a superuser delete', async function () {
      const forbidden = await call(api.deleteNote, fakeReq(bob, { params: { noteId: note.id } }))
      assert.strictEqual(forbidden.statusCode, 403)
      const res = await call(api.deleteNote, fakeReq(admin, { params: { noteId: note.id } }))
      assert.strictEqual(res.statusCode, 204)
      assert.strictEqual(await models.Note.findByPk(note.id), null)
    })

    it('refuses to delete a note without owner, even for a superuser', async function () {
      const orphan = await models.Note.create({ content: 'x' })
      const res = await call(api.deleteNote, fakeReq(admin, { params: { noteId: orphan.id } }))
      assert.strictEqual(res.statusCode, 403)
    })
  })
})
