'use strict'

// Personal REST API on notes, authenticated by the user's API token. It acts
// with the rights the user has in the web UI.

const Router = require('express').Router
const bodyParser = require('body-parser')
const Sequelize = require('sequelize')

const auth = require('./auth')
const config = require('../config')
const history = require('../history')
const logger = require('../logger')
const models = require('../models')
const realtime = require('../realtime')
const { mayView, mayEdit, mayManage, mayDelete } = require('../permissions')
const { markdownParser } = require('./utils')
const { noteToEntry } = require('./apiRouter')
const { createApiTokenCheck } = require('./auth/apiToken')

const apiV1Router = module.exports = Router()

const jsonParser = bodyParser.json({ type: 'application/json', limit: '10kb' })
const editableFields = ['permission', 'url']
const noteAttributes = ['id', 'alias', 'title', 'content', 'permission', 'ownerId', 'createdAt', 'lastchangeAt']
const ownerInclude = { model: models.User, as: 'owner', attributes: ['id', 'profile'] }

function requestError (message, status) {
  return Object.assign(new Error(message), { status })
}

function sendError (res, err) {
  if (err.status) return res.status(err.status).json({ error: err.message })
  logger.error('api v1: ' + err)
  return res.status(500).json({ error: 'internal error' })
}

// wraps an async handler so that its errors become JSON responses
function handler (fn) {
  return function (req, res) {
    return Promise.resolve(fn(req, res)).catch(err => sendError(res, err))
  }
}

function noteUrl (note) {
  return note.alias ? note.alias : models.Note.encodeNoteId(note.id)
}

// The note `noteId` (id, url or shortid) if `user` may view it. A note the
// user may not view is reported as missing, so its existence stays hidden.
async function findViewableNote (noteId, user) {
  const id = await realtime.findNoteId(noteId)
  const note = id && await models.Note.findOne({
    where: { id },
    attributes: noteAttributes,
    include: [ownerInclude]
  })
  if (!note || !mayView(user, note.permission, note.ownerId)) throw requestError('note not found', 404)
  return note
}

// the raw Markdown body of a request, without carriage returns
function textBody (req) {
  if (typeof req.body !== 'string') {
    throw requestError('text/markdown or text/plain body required', 415)
  }
  const content = req.body.replace(/\r/g, '')
  if (content.length > config.documentMaxLength) throw requestError('note too long', 413)
  return content
}

// opaque tag of an If-Match header, ignoring a weak marker added by proxies
function ifMatchTag (header) {
  const tag = String(header).trim()
  return tag.startsWith('W/') ? tag.slice(2) : tag
}

function getHistory (userId) {
  return new Promise(function (resolve, reject) {
    history.getHistory(userId, (err, items) => err ? reject(err) : resolve(items || {}))
  })
}

// ids (from encoded ids) and aliases named by the keys of a user's history
function splitHistoryIds (keys) {
  const ids = []
  const aliases = []
  keys.forEach(function (key) {
    let id = null
    try {
      id = models.Note.decodeNoteId(key)
    } catch (err) {}
    if (id && models.Note.checkNoteIdValid(id)) ids.push(id)
    else aliases.push(key)
  })
  return { ids, aliases }
}

// notes owned by the user and notes in their history, if viewable
async function listNotes (req, res) {
  const user = req.apiUser
  const { ids, aliases } = splitHistoryIds(Object.keys(await getHistory(user.id)))
  const notes = await models.Note.findAll({
    where: {
      [Sequelize.Op.or]: [{ ownerId: user.id }, { id: ids }, { alias: aliases }]
    },
    attributes: noteAttributes,
    include: [ownerInclude],
    order: [['lastchangeAt', 'DESC']]
  })
  res.json(notes
    .filter(note => mayView(user, note.permission, note.ownerId))
    .map(noteToEntry))
}

async function createNote (req, res) {
  const user = req.apiUser
  const content = textBody(req)
  const alias = req.query.url
  if (alias !== undefined) {
    if (!config.allowFreeURL) throw requestError('free URLs are disabled', 403)
    await realtime.checkNoteAlias(alias)
  }
  let note
  try {
    note = await models.Note.create({
      ownerId: user.id,
      alias: alias === undefined ? null : alias,
      content,
      title: models.Note.parseNoteTitle(content)
    })
  } catch (err) {
    if (err.name === 'SequelizeUniqueConstraintError') throw requestError('url already in use', 409)
    throw err
  }
  logger.info(`api v1: user ${user.id} created note ${note.id}`)
  const created = await findViewableNote(note.id, user)
  const { etag } = await realtime.getNoteContent(note.id)
  res.status(201)
    .set('Location', `${config.serverURL}/api/v1/notes/${noteUrl(created)}`)
    .set('ETag', etag)
    .json(noteToEntry(created))
}

async function getNote (req, res) {
  const note = await findViewableNote(req.params.noteId, req.apiUser)
  const { content, etag } = await realtime.getNoteContent(note.id)
  res.set('ETag', etag)
  if (req.accepts(['application/json', 'text/markdown']) === 'text/markdown') {
    return res.type('text/markdown; charset=utf-8').send(content)
  }
  res.json(Object.assign(noteToEntry(note), { content }))
}

// the note `noteId` if `user` may edit its content
async function findEditableNote (noteId, user) {
  const note = await findViewableNote(noteId, user)
  if (!mayEdit(user, note.permission, note.ownerId)) throw requestError('forbidden', 403)
  return note
}

async function replaceContent (req, res) {
  const user = req.apiUser
  const note = await findEditableNote(req.params.noteId, user)
  const header = req.get('If-Match')
  if (!header) throw requestError('If-Match header required, use the ETag of GET or *', 428)
  const content = textBody(req)
  const expected = ifMatchTag(header)
  const { etag } = await realtime.writeNoteContent(note.id, function (current) {
    if (expected !== '*' && expected !== realtime.contentETag(current)) {
      throw requestError('note changed since this ETag', 412)
    }
    return content
  }, user.id)
  res.set('ETag', etag).status(204).end()
}

async function appendContent (req, res) {
  const user = req.apiUser
  const note = await findEditableNote(req.params.noteId, user)
  const text = textBody(req)
  const { etag } = await realtime.writeNoteContent(note.id, function (current) {
    const separator = current && !current.endsWith('\n') ? '\n' : ''
    return current + separator + text
  }, user.id)
  res.set('ETag', etag).status(204).end()
}

// Checks the PATCH body and returns the changes it asks for.
function parseChanges (body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw requestError('JSON object body required', 400)
  }
  const keys = Object.keys(body)
  const unknown = keys.filter(key => !editableFields.includes(key))
  if (unknown.length) throw requestError('unknown field: ' + unknown.join(', '), 400)
  if (!keys.length) throw requestError('nothing to change', 400)
  if ('permission' in body) {
    const invalid = realtime.checkNotePermission(body.permission)
    if (invalid) throw invalid
  }
  if ('url' in body && body.url !== null && typeof body.url !== 'string') {
    throw requestError('url must be a string or null', 400)
  }
  return body
}

async function patchNote (req, res) {
  const user = req.apiUser
  const changes = parseChanges(req.body)
  const note = await findViewableNote(req.params.noteId, user)
  if (!mayManage(user, note.ownerId)) throw requestError('forbidden', 403)
  // giving a free URL is an API-only power, bound to the same setting as /new/:noteId
  if (changes.url && !config.allowFreeURL) throw requestError('free URLs are disabled', 403)
  if ('url' in changes) await realtime.setNoteAlias(note.id, changes.url)
  if ('permission' in changes) await realtime.setNotePermission(note.id, changes.permission)
  logger.info(`api v1: user ${user.id} changed ${Object.keys(changes).join(', ')} of note ${note.id}`)
  res.json(noteToEntry(await models.Note.findOne({
    where: { id: note.id },
    attributes: noteAttributes,
    include: [ownerInclude]
  })))
}

async function deleteNote (req, res) {
  const user = req.apiUser
  const note = await findViewableNote(req.params.noteId, user)
  if (!mayDelete(user, note.ownerId)) throw requestError('forbidden', 403)
  await realtime.deleteNote(note.id)
  logger.info(`api v1: user ${user.id} deleted note ${note.id}`)
  res.status(204).end()
}

// the auth router is looked up at each request, so that tests can replace it
apiV1Router.use('/api/v1', createApiTokenCheck({ isAllowed: user => auth.isSessionAllowed(user) }))
apiV1Router.get('/api/v1/notes', handler(listNotes))
apiV1Router.post('/api/v1/notes', markdownParser, handler(createNote))
apiV1Router.get('/api/v1/notes/:noteId', handler(getNote))
apiV1Router.put('/api/v1/notes/:noteId/content', markdownParser, handler(replaceContent))
apiV1Router.post('/api/v1/notes/:noteId/content/append', markdownParser, handler(appendContent))
apiV1Router.patch('/api/v1/notes/:noteId', jsonParser, handler(patchNote))
apiV1Router.delete('/api/v1/notes/:noteId', handler(deleteNote))
// unknown API paths must not reach the note router
apiV1Router.use('/api/v1', (req, res) => res.status(404).json({ error: 'not found' }))

Object.assign(module.exports, {
  listNotes,
  createNote,
  getNote,
  replaceContent,
  appendContent,
  patchNote,
  deleteNote,
  parseChanges,
  ifMatchTag,
  splitHistoryIds
})
