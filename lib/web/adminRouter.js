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

// value of ?owner=, lower-cased; '' (all notes) when absent or not a single string
function ownerFilterOf (query) {
  const owner = query && query.owner
  return typeof owner === 'string' ? owner.toLowerCase() : ''
}

// '' matches every note, 'none' the notes without owner, anything else an ownerId
function matchesOwner (note, filter) {
  if (!filter) return true
  if (filter === 'none') return !note.ownerId
  return !!note.ownerId && String(note.ownerId).toLowerCase() === filter
}

// one entry per distinct owner of the listed notes, with its number of notes
function ownerChoices (notes) {
  const byOwner = new Map()
  let unowned = 0
  notes.forEach(function (note) {
    if (!note.ownerId) {
      unowned++
      return
    }
    const value = String(note.ownerId).toLowerCase()
    const choice = byOwner.get(value)
    if (choice) {
      choice.count++
    } else {
      // several deleted users must stay distinguishable
      const label = note.ownerLogin === '(unknown)' ? '(unknown) ' + value.slice(0, 8) : note.ownerLogin
      byOwner.set(value, { value, label, count: 1 })
    }
  })
  const choices = Array.from(byOwner.values())
    .sort((a, b) => String(a.label).localeCompare(String(b.label)))
  if (unowned) choices.unshift({ value: 'none', label: '(none)', count: unowned })
  return choices
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
    const all = notes.map(note => ({
      id: note.id,
      url: note.alias ? note.alias : models.Note.encodeNoteId(note.id),
      title: note.title || 'Untitled',
      permission: note.permission,
      ownerId: note.ownerId,
      ownerLogin: note.ownerId ? (loginById.get(note.ownerId) || '(unknown)') : '(none)',
      lastchange: note.lastchangeAt ? note.lastchangeAt.toISOString().slice(0, 16).replace('T', ' ') : ''
    }))
    const ownerFilter = ownerFilterOf(req.query)
    const choices = ownerChoices(all)
    const active = choices.find(choice => choice.value === ownerFilter)
    res.render('admin.ejs', {
      title: 'Admin - HedgeDoc',
      opengraph: [],
      users,
      permissions: ['freely', 'editable', 'limited', 'locked', 'protected', 'private'],
      notes: all.filter(note => matchesOwner(note, ownerFilter)),
      totalNotes: all.length,
      ownerFilter,
      ownerChoices: choices,
      ownerLabel: active ? active.label : '(unknown owner)'
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

module.exports.ownerFilterOf = ownerFilterOf
module.exports.matchesOwner = matchesOwner
module.exports.ownerChoices = ownerChoices
