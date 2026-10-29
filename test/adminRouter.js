'use strict'

const assert = require('assert')

const { ownerFilterOf, matchesOwner, ownerChoices } = require('../lib/web/adminRouter')

const ALICE = '6a1f2c3d-0000-4000-8000-000000000001'
const BOB = '7b2e3d4c-0000-4000-8000-000000000002'
const GONE1 = '8c3d4e5f-0000-4000-8000-000000000003'
const GONE2 = '9d4e5f60-0000-4000-8000-000000000004'

describe('admin owner filter', function () {
  describe('ownerFilterOf', function () {
    it('is empty without owner parameter', function () {
      assert.strictEqual(ownerFilterOf({}), '')
      assert.strictEqual(ownerFilterOf(undefined), '')
    })

    it('lower-cases a string', function () {
      assert.strictEqual(ownerFilterOf({ owner: ALICE.toUpperCase() }), ALICE)
      assert.strictEqual(ownerFilterOf({ owner: 'none' }), 'none')
    })

    it('ignores arrays and objects', function () {
      assert.strictEqual(ownerFilterOf({ owner: [ALICE, BOB] }), '')
      assert.strictEqual(ownerFilterOf({ owner: { x: '1' } }), '')
    })
  })

  describe('matchesOwner', function () {
    const owned = { ownerId: ALICE }
    const unowned = { ownerId: null }

    it('matches everything without filter', function () {
      assert.strictEqual(matchesOwner(owned, ''), true)
      assert.strictEqual(matchesOwner(unowned, ''), true)
    })

    it('matches notes without owner for none', function () {
      assert.strictEqual(matchesOwner(owned, 'none'), false)
      assert.strictEqual(matchesOwner(unowned, 'none'), true)
      assert.strictEqual(matchesOwner({}, 'none'), true)
    })

    it('matches by owner id', function () {
      assert.strictEqual(matchesOwner(owned, ALICE), true)
      assert.strictEqual(matchesOwner({ ownerId: ALICE.toUpperCase() }, ALICE), true)
      assert.strictEqual(matchesOwner(owned, BOB), false)
      assert.strictEqual(matchesOwner(unowned, BOB), false)
    })
  })

  describe('ownerChoices', function () {
    it('counts notes per owner, none first, then by label', function () {
      const choices = ownerChoices([
        { ownerId: BOB, ownerLogin: 'bob' },
        { ownerId: ALICE, ownerLogin: 'alice' },
        { ownerId: null, ownerLogin: '(none)' },
        { ownerId: BOB, ownerLogin: 'bob' }
      ])
      assert.deepStrictEqual(choices, [
        { value: 'none', label: '(none)', count: 1 },
        { value: ALICE, label: 'alice', count: 1 },
        { value: BOB, label: 'bob', count: 2 }
      ])
    })

    it('has no none entry when every note has an owner', function () {
      const choices = ownerChoices([{ ownerId: ALICE, ownerLogin: 'alice' }])
      assert.deepStrictEqual(choices.map(choice => choice.value), [ALICE])
    })

    it('gives distinct labels to unknown owners', function () {
      const choices = ownerChoices([
        { ownerId: GONE1, ownerLogin: '(unknown)' },
        { ownerId: GONE2, ownerLogin: '(unknown)' }
      ])
      assert.deepStrictEqual(choices.map(choice => choice.label), [
        '(unknown) ' + GONE1.slice(0, 8),
        '(unknown) ' + GONE2.slice(0, 8)
      ])
    })

    it('is empty without notes', function () {
      assert.deepStrictEqual(ownerChoices([]), [])
    })
  })
})
