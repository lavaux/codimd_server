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

describe('note permission rules', function () {
  const { mayView, mayEdit, mayManage, mayDelete } = require('../lib/permissions')
  const guest = null
  const member = { id: 'member' }
  const own = { id: 'owner' }
  const admin = { id: 'admin', superuser: true }
  const users = { guest, member, own, admin }

  // expected results for [guest, member, owner, superuser]
  const viewTable = {
    freely: [true, true, true, true],
    editable: [true, true, true, true],
    limited: [false, true, true, true],
    locked: [true, true, true, true],
    protected: [false, true, true, true],
    private: [false, false, true, true],
    bogus: [false, false, false, false]
  }
  const editTable = {
    freely: [true, true, true, true],
    editable: [false, true, true, true],
    limited: [false, true, true, true],
    locked: [false, false, true, true],
    protected: [false, false, true, true],
    private: [false, false, true, true],
    bogus: [false, false, false, false]
  }

  for (const [rule, table] of [[mayView, viewTable], [mayEdit, editTable]]) {
    for (const permission of Object.keys(table)) {
      it(`${rule.name} on a ${permission} note`, function () {
        const got = Object.values(users).map(user => rule(user, permission, 'owner'))
        assert.deepStrictEqual(got, table[permission])
      })
    }
  }

  it('lets only the owner and superusers manage a note', function () {
    assert.deepStrictEqual(Object.values(users).map(user => mayManage(user, 'owner')), [false, false, true, true])
    assert.strictEqual(mayManage(admin, null), true)
    assert.strictEqual(mayManage(member, null), false)
  })

  it('does not let anyone delete a note without owner', function () {
    assert.deepStrictEqual(Object.values(users).map(user => mayDelete(user, 'owner')), [false, false, true, true])
    assert.strictEqual(mayDelete(admin, null), false)
  })

  it('hides a note with an unknown permission from the HTTP check', function () {
    assert.strictEqual(checkViewPermission(request(superuser), { permission: 'bogus', ownerId: 'admin' }), false)
  })
})
