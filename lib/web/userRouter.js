'use strict'

import { ZipArchive } from 'archiver'
import { createRequire } from 'module'
const require = createRequire(import.meta.url)

const sanitizeFilename = require('sanitize-filename')
const async = require('async')
const Router = require('express').Router

const errors = require('../errors')
const config = require('../config')
const models = require('../models')
const logger = require('../logger')
const { generateAvatar } = require('../letter-avatars')
const { issueToken, revokeToken, tokenInfo } = require('./auth/apiToken')

const UserRouter = Router()
export default UserRouter

// get me info
UserRouter.get('/me', function (req, res) {
  if (req.isAuthenticated()) {
    models.User.findOne({
      where: {
        id: req.user.id
      }
    }).then(function (user) {
      if (!user) { return errors.errorNotFound(res) }
      const profile = models.User.getProfile(user)
      res.send({
        status: 'ok',
        id: req.user.id,
        name: profile.name,
        photo: profile.photo,
        superuser: user.superuser === true,
        apiToken: tokenInfo(user)
      })
    }).catch(function (err) {
      logger.error('read me failed: ' + err)
      return errors.errorInternalError(res)
    })
  } else {
    res.send({
      status: 'forbidden'
    })
  }
})

// A cross-site form cannot send application/json without a CORS preflight,
// which this server never grants, so requiring it guards against CSRF.
function requireJSONRequest (req, res, next) {
  if (!req.isAuthenticated()) return res.status(403).json({ error: 'login required' })
  if (!req.is('application/json')) {
    return res.status(415).json({ error: 'Content-Type: application/json required' })
  }
  next()
}

function findMe (req) {
  return models.User.findOne({ where: { id: req.user.id } }).then(function (user) {
    if (!user) throw new Error('user not found')
    return user
  })
}

// create or rotate the personal API token; it is shown only in this response
UserRouter.post('/me/api-token', requireJSONRequest, function (req, res) {
  findMe(req).then(issueToken).then(function ({ token, createdAt, expiresAt }) {
    logger.info(`api token: user ${req.user.id} generated a token`)
    res.set('Cache-Control', 'no-store').json({ token, createdAt, expiresAt })
  }).catch(function (err) {
    logger.error('api token: generation failed: ' + err)
    return errors.errorInternalError(res)
  })
})

UserRouter.delete('/me/api-token', requireJSONRequest, function (req, res) {
  findMe(req).then(revokeToken).then(function () {
    logger.info(`api token: user ${req.user.id} revoked their token`)
    res.status(204).end()
  }).catch(function (err) {
    logger.error('api token: revocation failed: ' + err)
    return errors.errorInternalError(res)
  })
})

// delete the currently authenticated user
UserRouter.get('/me/delete/:token?', function (req, res) {
  if (req.isAuthenticated()) {
    models.User.findOne({
      where: {
        id: req.user.id
      }
    }).then(function (user) {
      if (!user) {
        return errors.errorNotFound(res)
      }
      if (user.deleteToken === req.params.token) {
        user.destroy().then(function () {
          res.redirect(config.serverURL + '/')
        })
      } else {
        return errors.errorForbidden(res)
      }
    }).catch(function (err) {
      logger.error('delete user failed: ' + err)
      return errors.errorInternalError(res)
    })
  } else {
    return errors.errorForbidden(res)
  }
})

// export the data of the authenticated user
UserRouter.get('/me/export', function (req, res) {
  if (req.isAuthenticated()) {
    // let output = fs.createWriteStream(__dirname + '/example.zip');
    const archive = new ZipArchive({
      zlib: { level: 3 } // Sets the compression level.
    })
    res.setHeader('Content-Type', 'application/zip')
    res.attachment('archive.zip')
    archive.pipe(res)
    archive.on('error', function (err) {
      logger.error('export user data failed: ' + err)
      return errors.errorInternalError(res)
    })
    models.User.findOne({
      where: {
        id: req.user.id
      }
    }).then(function (user) {
      models.Note.findAll({
        where: {
          ownerId: user.id
        }
      }).then(function (notes) {
        const filenames = {}
        async.each(notes, function (note, callback) {
          const basename = sanitizeFilename(note.title, { replacement: '_' })
          let filename
          let suffix = ''
          do {
            const seperator = typeof suffix === 'number' ? '-' : ''
            filename = basename + seperator + suffix + '.md'
            suffix++
          } while (filenames[filename])
          filenames[filename] = true

          logger.debug('Write: ' + filename)
          archive.append(Buffer.from(note.content), { name: filename, date: note.lastchangeAt })
          callback(null, null)
        }, function (err) {
          if (err) {
            return errors.errorInternalError(res)
          }

          archive.finalize()
        })
      })
    }).catch(function (err) {
      logger.error('export user data failed: ' + err)
      return errors.errorInternalError(res)
    })
  } else {
    return errors.errorForbidden(res)
  }
})

UserRouter.get('/user/:username/avatar.svg', function (req, res, next) {
  res.setHeader('Content-Type', 'image/svg+xml')
  res.setHeader('Cache-Control', 'public, max-age=86400')
  res.send(generateAvatar(req.params.username))
})
