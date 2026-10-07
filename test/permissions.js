'use strict'

const assert = require('assert')

const { checkViewPermission } = require('../lib/web/note/util')
const { isSuperuser } = require('../lib/utils')

function request (user) {
  return {
    user,
    isAuthenticated: () => !!user
  }
}

const owner = { id: 'owner' }
const other = { id: 'other', superuser: false }
const superuser = { id: 'admin', superuser: true }

describe('checkViewPermission', function () {
  const privateNote = { permission: 'private', ownerId: 'owner' }

  it('lets the owner read a private note', function () {
    assert.strictEqual(checkViewPermission(request(owner), privateNote), true)
  })

  it('hides a private note from other users', function () {
    assert.strictEqual(checkViewPermission(request(other), privateNote), false)
  })

  it('lets a superuser read a private note', function () {
    assert.strictEqual(checkViewPermission(request(superuser), privateNote), true)
  })

  it('hides a private note from guests', function () {
    assert.strictEqual(checkViewPermission(request(null), privateNote), false)
  })

  it('keeps protected notes readable by any signed-in user only', function () {
    const note = { permission: 'protected', ownerId: 'owner' }
    assert.strictEqual(checkViewPermission(request(other), note), true)
    assert.strictEqual(checkViewPermission(request(null), note), false)
  })
})

describe('isSuperuser', function () {
  it('is true only for an explicit true flag', function () {
    assert.strictEqual(isSuperuser(superuser), true)
    assert.strictEqual(isSuperuser(other), false)
    assert.strictEqual(isSuperuser({ id: 'x', superuser: null }), false)
    assert.strictEqual(isSuperuser(null), false)
  })
})
