'use strict'

const assert = require('assert')

const { checkWorkspaceMembership } = require('../lib/web/auth/oauth2/workspace')

// fake node-oauth client serving one response per page
function fakeClient (pages) {
  const client = {
    urls: [],
    get (url, accessToken, cb) {
      client.urls.push(url)
      assert.strictEqual(accessToken, 'token')
      const page = parseInt(new URL(url).searchParams.get('page'), 10)
      const response = pages[page - 1]
      if (response instanceof Error) return cb(response)
      cb(null, typeof response === 'string' ? response : JSON.stringify(response || []))
    }
  }
  return client
}

const URL_ORGS = 'https://forge.example.org/api/v1/user/orgs'

describe('oauth2 checkWorkspaceMembership', function () {
  it('accepts a member found on the first page', function (done) {
    const client = fakeClient([[{ username: 'other' }, { username: 'Aquila-consortium' }]])
    checkWorkspaceMembership(client, 'token', URL_ORGS, 'Aquila-consortium', function (err, isMember) {
      assert.ifError(err)
      assert.strictEqual(isMember, true)
      assert.strictEqual(client.urls.length, 1)
      assert.strictEqual(client.urls[0], URL_ORGS + '?page=1&limit=50')
      done()
    })
  })

  it('accepts a member found on a later page', function (done) {
    const client = fakeClient([[{ username: 'a' }], [{ username: 'Aquila-consortium' }]])
    checkWorkspaceMembership(client, 'token', URL_ORGS, 'Aquila-consortium', function (err, isMember) {
      assert.ifError(err)
      assert.strictEqual(isMember, true)
      assert.strictEqual(client.urls.length, 2)
      done()
    })
  })

  it('rejects a non-member once an empty page is reached', function (done) {
    const client = fakeClient([[{ username: 'a' }], [{ username: 'b' }], []])
    checkWorkspaceMembership(client, 'token', URL_ORGS, 'Aquila-consortium', function (err, isMember) {
      assert.ifError(err)
      assert.strictEqual(isMember, false)
      assert.strictEqual(client.urls.length, 3)
      done()
    })
  })

  it('matches the organization name case-insensitively', function (done) {
    const client = fakeClient([[{ username: 'aquila-CONSORTIUM' }]])
    checkWorkspaceMembership(client, 'token', URL_ORGS, 'Aquila-consortium', function (err, isMember) {
      assert.ifError(err)
      assert.strictEqual(isMember, true)
      done()
    })
  })

  it('passes HTTP errors through', function (done) {
    const client = fakeClient([new Error('403')])
    checkWorkspaceMembership(client, 'token', URL_ORGS, 'Aquila-consortium', function (err, isMember) {
      assert.ok(err)
      assert.strictEqual(isMember, undefined)
      done()
    })
  })

  it('reports invalid JSON as an error', function (done) {
    const client = fakeClient(['not json'])
    checkWorkspaceMembership(client, 'token', URL_ORGS, 'Aquila-consortium', function (err) {
      assert.ok(err)
      done()
    })
  })
})
