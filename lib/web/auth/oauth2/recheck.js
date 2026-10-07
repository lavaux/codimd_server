'use strict'

const { checkWorkspaceMembership } = require('./workspace')

// delay before retrying after Forgejo could not be reached
const RETRY_DELAY = 60 * 1000

// Creates `isStillMember(user)`, which resolves to false once a logged-in
// user is known to have left `workspace`. The membership is queried at most
// every `interval` ms per user. An expired access token is renewed with the
// stored refresh token, and the new tokens are saved on the user.
// Transient failures (network, 5xx) keep the user logged in and retry after
// RETRY_DELAY, so that a Forgejo outage does not log everybody out.
// Without a `workspace`, membership is not queried and every user stays.
// The optional `refreshPrivileges(user)` runs after each successful check.
// If it rejects, the user stays logged in with the privileges stored on the
// user, and both are checked again after RETRY_DELAY.
function createMembershipChecker ({ oauth2Client, workspacesURL, workspace, interval, logger, refreshPrivileges, now = Date.now }) {
  // user id -> { nextCheck, pending }
  const state = new Map()

  function queryMembership (accessToken) {
    return new Promise((resolve, reject) => {
      checkWorkspaceMembership(oauth2Client, accessToken, workspacesURL, workspace, (err, isMember) => {
        if (err) return reject(err)
        resolve(isMember)
      })
    })
  }

  function refreshTokens (user) {
    return new Promise((resolve, reject) => {
      if (!user.refreshToken) return reject(Object.assign(new Error('No refresh token'), { statusCode: 401 }))
      oauth2Client.getOAuthAccessToken(user.refreshToken, { grant_type: 'refresh_token' }, (err, accessToken, refreshToken) => {
        if (err) return reject(err)
        user.accessToken = accessToken
        if (refreshToken) user.refreshToken = refreshToken
        resolve(user.save())
      })
    })
  }

  // 400/401/403 mean the token or grant is no longer valid
  function isDefinitive (err) {
    return [400, 401, 403].includes(err.statusCode)
  }

  async function check (user) {
    if (!workspace) return true
    try {
      return await queryMembership(user.accessToken)
    } catch (err) {
      if (err.statusCode !== 401) throw err
    }
    await refreshTokens(user)
    return queryMembership(user.accessToken)
  }

  return function isStillMember (user) {
    let entry = state.get(user.id)
    if (!entry) {
      // first request after login or after a server restart
      entry = { nextCheck: 0, pending: null }
      state.set(user.id, entry)
    }
    if (entry.pending) return entry.pending
    if (now() < entry.nextCheck) return Promise.resolve(true)

    entry.pending = check(user).then(async isMember => {
      entry.nextCheck = now() + interval
      if (!isMember) {
        logger.info(`oauth2: user ${user.id} is no longer a member of workspace "${workspace}", ending session`)
        state.delete(user.id)
        return false
      }
      if (refreshPrivileges) {
        try {
          await refreshPrivileges(user)
        } catch (err) {
          logger.warn(`oauth2: privilege recheck of user ${user.id} failed, keeping the stored privileges: ${err.message || JSON.stringify(err)}`)
          entry.nextCheck = now() + RETRY_DELAY
        }
      }
      return true
    }, err => {
      if (isDefinitive(err)) {
        logger.info(`oauth2: cannot renew access of user ${user.id} (HTTP ${err.statusCode}), ending session`)
        state.delete(user.id)
        return false
      }
      logger.warn(`oauth2: membership recheck of user ${user.id} failed, retrying later: ${err.message || JSON.stringify(err)}`)
      entry.nextCheck = now() + RETRY_DELAY
      return true
    }).finally(() => {
      entry.pending = null
    })
    return entry.pending
  }
}

module.exports = { createMembershipChecker }
