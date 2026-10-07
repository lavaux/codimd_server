'use strict'

const crypto = require('crypto')
const Router = require('express').Router
const bodyParser = require('body-parser')

const config = require('../config')
const logger = require('../logger')
const models = require('../models')
const realtime = require('../realtime')
const { loginOf } = require('../utils')

const apiRouter = module.exports = Router()

// Only application/json bodies are parsed.
const jsonParser = bodyParser.json({ type: 'application/json', limit: '10kb' })
const editableFields = ['permission', 'owner', 'url']

function digest (value) {
  return crypto.createHash('sha256').update(String(value)).digest()
}

// Middleware accepting only requests with `Authorization: Bearer <token>`.
// Without a configured token the endpoint does not exist.
function createTokenCheck (token) {
  const expected = token ? digest(token) : null
  return function (req, res, next) {
    if (!expected) return res.status(404).json({ error: 'not found' })
    const match = /^Bearer (.+)$/i.exec(req.get('Authorization') || '')
    if (!match || !crypto.timingSafeEqual(digest(match[1]), expected)) {
      return res.status(401).json({ error: 'unauthorized' })
    }
    next()
  }
}

function tagsOf (note) {
  try {
    return models.Note.parseNoteInfo(note.content).tags
  } catch (err) {
    logger.warn(`api: cannot parse tags of note ${note.id}: ${err}`)
    return []
  }
}

function noteToEntry (note) {
  return {
    id: note.id,
    url: note.alias ? note.alias : models.Note.encodeNoteId(note.id),
    title: note.title || 'Untitled',
    tags: tagsOf(note),
    permission: note.permission,
    owner: note.owner ? loginOf(note.owner) : null,
    createdAt: note.createdAt,
    lastchangeAt: note.lastchangeAt
  }
}

const noteAttributes = ['id', 'alias', 'title', 'content', 'permission', 'ownerId', 'createdAt', 'lastchangeAt']
const ownerInclude = { model: models.User, as: 'owner', attributes: ['id', 'profile'] }

function requestError (message, status) {
  return Object.assign(new Error(message), { status })
}

function sendError (res, err) {
  if (err.status) return res.status(err.status).json({ error: err.message })
  logger.error('api: ' + err)
  return res.status(500).json({ error: 'internal error' })
}

// note id from any form the listing or the web UI use: id, url, shortid
function resolveNoteId (noteId) {
  return realtime.findNoteId(noteId).then(function (id) {
    if (!id) throw requestError('note not found', 404)
    return id
  })
}

// Forgejo logins are unique regardless of case
function findUserByLogin (login) {
  const wanted = String(login).toLowerCase()
  return models.User.findAll({ attributes: ['id', 'profile'] }).then(function (users) {
    const user = users.find(function (user) {
      const login = loginOf(user)
      return typeof login === 'string' && login.toLowerCase() === wanted
    })
    if (!user) throw requestError('user not found', 404)
    return user
  })
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
  if ('owner' in body && (typeof body.owner !== 'string' || !body.owner)) {
    throw requestError('owner must be a Forgejo login', 400)
  }
  if ('url' in body && body.url !== null && typeof body.url !== 'string') {
    throw requestError('url must be a string or null', 400)
  }
  return body
}

const requireToken = createTokenCheck(config.aquila.token)

apiRouter.get('/api/notes', requireToken, function (req, res) {
  models.Note.findAll({
    attributes: noteAttributes,
    include: [ownerInclude],
    order: [['lastchangeAt', 'DESC']]
  }).then(function (notes) {
    res.json(notes.map(noteToEntry))
  }).catch(function (err) {
    logger.error('api: listing notes failed: ' + err)
    res.status(500).json({ error: 'internal error' })
  })
})

// Changes the permission, owner (Forgejo login) and url (alias, null to
// remove it) of a note, and returns the updated note. The url is applied
// first because it is the change most likely to be refused.
apiRouter.patch('/api/notes/:noteId', requireToken, jsonParser, async function (req, res) {
  try {
    const changes = parseChanges(req.body)
    const noteId = await resolveNoteId(req.params.noteId)
    const owner = 'owner' in changes ? await findUserByLogin(changes.owner) : null
    if ('url' in changes) await realtime.setNoteAlias(noteId, changes.url)
    if (owner) await realtime.setNoteOwner(noteId, owner.id)
    if ('permission' in changes) await realtime.setNotePermission(noteId, changes.permission)
    logger.info(`api: changed ${Object.keys(changes).join(', ')} of note ${noteId}`)
    const note = await models.Note.findOne({
      where: { id: noteId },
      attributes: noteAttributes,
      include: [ownerInclude]
    })
    res.json(noteToEntry(note))
  } catch (err) {
    sendError(res, err)
  }
})

module.exports.createTokenCheck = createTokenCheck
module.exports.noteToEntry = noteToEntry
module.exports.parseChanges = parseChanges
module.exports.findUserByLogin = findUserByLogin
