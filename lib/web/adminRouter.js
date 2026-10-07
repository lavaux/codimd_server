'use strict'

const Router = require('express').Router
const bodyParser = require('body-parser')

const errors = require('../errors')
const logger = require('../logger')
const models = require('../models')
const realtime = require('../realtime')
const { isSuperuser, loginOf } = require('../utils')

const adminRouter = module.exports = Router()

// Only application/json bodies are parsed. A cross-site form cannot send that
// content type without a CORS preflight, which this server never grants.
const jsonParser = bodyParser.json({ type: 'application/json', limit: '10kb' })

function requireSuperuser (req, res, next) {
  if (!req.isAuthenticated() || !isSuperuser(req.user)) {
    return errors.errorForbidden(res)
  }
  next()
}

// users who have logged in at least once, i.e. who have an OAuth2 profile
function listUsers () {
  return models.User.findAll({
    attributes: ['id', 'profile']
  }).then(function (users) {
    return users
      .filter(user => user.profile)
      .map(user => ({
        id: user.id,
        login: loginOf(user),
        name: models.User.getProfile(user).name
      }))
      .sort((a, b) => String(a.login).localeCompare(String(b.login)))
  })
}

function sendManagementError (res, err) {
  if (err.status) {
    return res.status(err.status).json({ error: err.message })
  }
  logger.error('admin: ' + err)
  return res.status(500).json({ error: 'internal error' })
}

adminRouter.use('/admin', requireSuperuser)

adminRouter.get('/admin', function (req, res) {
  Promise.all([
    models.Note.findAll({
      attributes: ['id', 'shortid', 'alias', 'title', 'permission', 'ownerId', 'lastchangeAt'],
      order: [['lastchangeAt', 'DESC']]
    }),
    listUsers()
  ]).then(function ([notes, users]) {
    const loginById = new Map(users.map(user => [user.id, user.login]))
    res.render('admin.ejs', {
      title: 'Admin - HedgeDoc',
      opengraph: [],
      users,
      permissions: ['freely', 'editable', 'limited', 'locked', 'protected', 'private'],
      notes: notes.map(note => ({
        id: note.id,
        url: note.alias ? note.alias : models.Note.encodeNoteId(note.id),
        title: note.title || 'Untitled',
        permission: note.permission,
        ownerId: note.ownerId,
        ownerLogin: note.ownerId ? (loginById.get(note.ownerId) || '(unknown)') : '(none)',
        lastchange: note.lastchangeAt ? note.lastchangeAt.toISOString().slice(0, 16).replace('T', ' ') : ''
      }))
    })
  }).catch(function (err) {
    logger.error('admin: listing notes failed: ' + err)
    return errors.errorInternalError(res)
  })
})

adminRouter.get('/admin/users', function (req, res) {
  listUsers().then(users => res.json(users)).catch(err => sendManagementError(res, err))
})

adminRouter.post('/admin/notes/:noteId/permission', jsonParser, function (req, res) {
  const permission = req.body && req.body.permission
  realtime.setNotePermission(req.params.noteId, permission).then(function () {
    logger.info(`admin: user ${req.user.id} set permission of note ${req.params.noteId} to ${permission}`)
    res.json({ status: 'ok' })
  }).catch(err => sendManagementError(res, err))
})

adminRouter.post('/admin/notes/:noteId/owner', jsonParser, function (req, res) {
  const userId = req.body && req.body.userId
  if (!userId) return res.status(400).json({ error: 'userId required' })
  realtime.setNoteOwner(req.params.noteId, userId).then(function () {
    logger.info(`admin: user ${req.user.id} gave note ${req.params.noteId} to user ${userId}`)
    res.json({ status: 'ok' })
  }).catch(err => sendManagementError(res, err))
})
