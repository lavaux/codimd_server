'use strict'

const PAGE_LIMIT = 50
const MAX_PAGES = 20

// Checks whether the owner of `accessToken` belongs to the organization
// `workspace`, by paging through `workspacesURL` (e.g. Forgejo's
// /api/v1/user/orgs). Calls `callback(err, isMember)`.
function checkWorkspaceMembership (oauth2Client, accessToken, workspacesURL, workspace, callback) {
  const wanted = workspace.toLowerCase()
  const separator = workspacesURL.includes('?') ? '&' : '?'

  function fetchPage (page) {
    if (page > MAX_PAGES) return callback(null, false)
    const url = `${workspacesURL}${separator}page=${page}&limit=${PAGE_LIMIT}`
    oauth2Client.get(url, accessToken, function (err, body) {
      if (err) return callback(err)

      let orgs
      try {
        orgs = JSON.parse(body)
      } catch (ex) {
        return callback(new Error('Failed to parse workspace list'))
      }
      if (!Array.isArray(orgs)) return callback(new Error('Workspace list is not an array'))
      if (orgs.length === 0) return callback(null, false)

      const found = orgs.some(org => typeof org.username === 'string' && org.username.toLowerCase() === wanted)
      if (found) return callback(null, true)
      fetchPage(page + 1)
    })
  }

  fetchPage(1)
}

module.exports = { checkWorkspaceMembership }
