'use strict'

const TIMEOUT = 10 * 1000

// Asks aquila-website whether the Forgejo `login` is an Aquila superuser.
// Resolves to true or false. A 404 (unknown member) is a definitive false.
// Any other failure rejects, and the caller keeps the last known status.
async function fetchSuperuser ({ url, token, login, fetchImpl = fetch }) {
  const target = new URL(url)
  target.searchParams.set('username', login)

  const res = await fetchImpl(target.toString(), {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json'
    },
    signal: AbortSignal.timeout(TIMEOUT)
  })

  if (res.status === 404) return false
  if (res.status !== 200) {
    throw Object.assign(new Error(`aquila-website answered HTTP ${res.status}`), { statusCode: res.status })
  }

  const body = await res.json()
  if (typeof body.superuser !== 'boolean') {
    throw new Error('aquila-website answer has no boolean "superuser"')
  }
  return body.superuser
}

// Returns the Forgejo login stored in a user's OAuth2 profile, or null.
function loginOf (user) {
  try {
    const login = JSON.parse(user.profile).username
    return typeof login === 'string' && login !== '' ? login : null
  } catch (err) {
    return null
  }
}

// Creates `refreshPrivileges(user)` for createMembershipChecker. It stores
// aquila-website's answer in `user.superuser`, saving only on change.
// Without `url` or `token`, nobody is a superuser.
function createSuperuserRefresher ({ url, token, logger, fetchImpl }) {
  return async function refreshPrivileges (user) {
    let superuser = false
    if (url && token) {
      const login = loginOf(user)
      if (login) {
        superuser = await fetchSuperuser({ url, token, login, fetchImpl })
      }
    }
    if (user.superuser !== superuser) {
      logger.info(`aquila: user ${user.id} is ${superuser ? 'now' : 'no longer'} a superuser`)
      user.superuser = superuser
      await user.save()
    }
  }
}

module.exports = { fetchSuperuser, createSuperuserRefresher }
