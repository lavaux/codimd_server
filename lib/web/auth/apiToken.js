'use strict'

const crypto = require('crypto')

const logger = require('../../logger')
const models = require('../../models')

const TOKEN_PREFIX = 'hdt_'
// 32 random bytes in base64url, without padding
const TOKEN_PATTERN = /^hdt_[A-Za-z0-9_-]{43}$/
const TOKEN_LIFETIME = 30 * 24 * 3600 * 1000
// apiTokenLastUsedAt is written at most this often per user
const LAST_USED_RESOLUTION = 60 * 1000

function generateToken () {
  return TOKEN_PREFIX + crypto.randomBytes(32).toString('base64url')
}

function hashToken (token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex')
}

function tokenExpiresAt (user) {
  if (!user.apiTokenCreatedAt) return null
  return new Date(new Date(user.apiTokenCreatedAt).getTime() + TOKEN_LIFETIME)
}

function isTokenExpired (user, now = Date.now()) {
  const expiresAt = tokenExpiresAt(user)
  return !expiresAt || now >= expiresAt.getTime()
}

// Gives `user` a new token, replacing any previous one, and returns it. The
// token is shown once: only its hash is stored.
async function issueToken (user, now = Date.now()) {
  const token = generateToken()
  user.apiTokenHash = hashToken(token)
  user.apiTokenCreatedAt = new Date(now)
  user.apiTokenLastUsedAt = null
  await user.save()
  return { token, createdAt: user.apiTokenCreatedAt, expiresAt: tokenExpiresAt(user) }
}

async function revokeToken (user) {
  user.apiTokenHash = null
  user.apiTokenCreatedAt = null
  user.apiTokenLastUsedAt = null
  await user.save()
}

// The token's state as reported by /me, or null without a token.
function tokenInfo (user, now = Date.now()) {
  if (!user.apiTokenHash) return null
  return {
    createdAt: user.apiTokenCreatedAt,
    expiresAt: tokenExpiresAt(user),
    lastUsedAt: user.apiTokenLastUsedAt || null,
    expired: isTokenExpired(user, now)
  }
}

// The user owning `token`, or null. The lookup is by hash of a 256-bit random
// value, so its timing tells nothing useful about the stored hashes.
function findUserByToken (token) {
  if (typeof token !== 'string' || !TOKEN_PATTERN.test(token)) return Promise.resolve(null)
  return models.User.findOne({ where: { apiTokenHash: hashToken(token) } })
}

function unauthorized (res, body, error) {
  res.set('WWW-Authenticate', error ? `Bearer error="${error}"` : 'Bearer')
  return res.status(401).json(body)
}

// Middleware accepting requests with `Authorization: Bearer <personal token>`
// and setting req.apiUser. `isAllowed(user)` resolves to false for a user who
// may no longer log in (for example, who left the organization).
function createApiTokenCheck ({ isAllowed, now = Date.now }) {
  const lastWrite = new Map()

  function touch (user) {
    const time = now()
    if (time - (lastWrite.get(user.id) || 0) < LAST_USED_RESOLUTION) return
    lastWrite.set(user.id, time)
    models.User.update({ apiTokenLastUsedAt: new Date(time) }, { where: { id: user.id } })
      .catch(err => logger.error('api token: cannot record last use: ' + err))
  }

  return function requireApiToken (req, res, next) {
    const match = /^Bearer (\S+)$/i.exec(req.get('Authorization') || '')
    if (!match) return unauthorized(res, { error: 'unauthorized' })
    findUserByToken(match[1]).then(function (user) {
      if (!user) return unauthorized(res, { error: 'unauthorized' }, 'invalid_token')
      if (isTokenExpired(user, now())) {
        return unauthorized(res, { error: 'token expired', expiredAt: tokenExpiresAt(user) }, 'invalid_token')
      }
      return Promise.resolve(isAllowed(user)).then(function (allowed) {
        if (!allowed) {
          return unauthorized(res, { error: 'access revoked, log in again on the web' }, 'invalid_token')
        }
        req.apiUser = user
        touch(user)
        next()
      }, function (err) {
        logger.warn(`api token: cannot check access of user ${user.id}: ${err}`)
        res.status(503).json({ error: 'cannot check access, retry later' })
      })
    }).catch(function (err) {
      logger.error('api token: ' + err)
      res.status(500).json({ error: 'internal error' })
    })
  }
}

module.exports = {
  TOKEN_LIFETIME,
  generateToken,
  hashToken,
  tokenExpiresAt,
  isTokenExpired,
  issueToken,
  revokeToken,
  tokenInfo,
  findUserByToken,
  createApiTokenCheck
}
