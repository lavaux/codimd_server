'use strict'

// Note permission rules, shared by the HTTP routes, the realtime sockets and
// the /api/v1 API. `user` is the logged-in user, or null for a guest.

const { isSuperuser } = require('./utils')

function isOwnerOrSuperuser (user, ownerId) {
  return !!user && (isSuperuser(user) || (!!ownerId && user.id === ownerId))
}

function mayView (user, permission, ownerId) {
  switch (permission) {
    case 'freely': case 'editable': case 'locked':
      return true
    case 'limited': case 'protected':
      return !!user
    case 'private':
      return isOwnerOrSuperuser(user, ownerId)
    default:
      return false
  }
}

function mayEdit (user, permission, ownerId) {
  switch (permission) {
    case 'freely':
      return true
    case 'editable': case 'limited':
      return !!user
    case 'locked': case 'private': case 'protected':
      return isOwnerOrSuperuser(user, ownerId)
    default:
      return false
  }
}

// change the permission or the alias of a note
function mayManage (user, ownerId) {
  return isOwnerOrSuperuser(user, ownerId)
}

// even a superuser cannot delete a note without owner
function mayDelete (user, ownerId) {
  return !!ownerId && isOwnerOrSuperuser(user, ownerId)
}

module.exports = { mayView, mayEdit, mayManage, mayDelete }
