# API documentation
Several tasks of HedgeDoc can be automated through HTTP requests.
The available endpoints for this api are described in this document.
For code-autogeneration there is an OpenAPIv3-compatible description available [here](openapi.yml).

## Notes
These endpoints create notes, return information about them or export them.  
You have to replace *\<NOTE\>* with either the alias or id of a note you want to work on. 

| Endpoint                                       | HTTP-Method | Description                                                                                                                                                                                                                                                  |
| ---------------------------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `/new`                                         | `GET`       | **Creates a new note.**<br>A random id will be assigned and the content will equal to the template (blank by default). After note creation a redirect is issued to the created note.                                                                         |
| `/new`                                         | `POST`      | **Imports some markdown data into a new note.**<br>A random id will be assigned and the content will equal to the body of the received HTTP-request. The `Content-Type: text/markdown` header should be set on this request.                                 |
| `/new/<ALIAS>`                                 | `POST`      | **Imports some markdown data into a new note with a given alias.**<br>This endpoint equals to the above one except that the alias from the url will be assigned to the note if [FreeURL-mode](../configuration.md#users-and-privileges) is enabled. |
| `/<NOTE>/download` or `/s/<SHORT-ID>/download` | `GET`       | **Returns the raw markdown content of a note.**                                                                                                                                                                                                              |
| `/<NOTE>/publish`                              | `GET`       | **Redirects to the published version of the note.**                                                                                                                                                                                                          |
| `/<NOTE>/slide`                                | `GET`       | **Redirects to the slide-presentation of the note.**<br>This is only useful on notes which are designed to be slides.                                                                                                                                        |
| `/<NOTE>/info`                                 | `GET`       | **Returns metadata about the note.**<br>This includes the title and description of the note as well as the creation date and viewcount. The data is returned as a JSON object.                                                                               |
| `/<NOTE>/revision`                             | `GET`       | **Returns a list of the available note revisions.**<br>The list is returned as a JSON object with an array of revision-id and length associations. The revision-id equals to the timestamp when the revision was saved.                                      |
| `/<NOTE>/revision/<REVISION-ID>`               | `GET`       | **Returns the revision of the note with some metadata.**<br>The revision is returned as a JSON object with the content of the note and the authorship.                                                                                                       |
| `/<NOTE>/gist`                                 | `GET`       | **Creates a new GitHub Gist with the note's content.**<br>If [GitHub integration](../configuration.md#github-login) is configured, the user will be redirected to GitHub and a new Gist with the content of the note will be created.               |

## Note administration
These endpoints list every note on the server and change the permission, owner or URL of any note.
They are meant for scripts and do not use the session cookie.
Each request must carry the header `Authorization: Bearer <TOKEN>`, where `<TOKEN>` is the value of `aquila.token` ([`CMD_AQUILA_TOKEN`](../configuration.md#oauth2-login)).
If no token is configured, both endpoints answer HTTP 404.

| Endpoint            | HTTP-Method | Description                                                                                                                                                                                                                                                                                                  |
| ------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `/api/notes`        | `GET`       | **Returns every note.**<br>The list is returned as a JSON array, most recently changed note first. Each entry contains `id`, `url`, `title`, `tags`, `permission`, `owner`, `createdAt` and `lastchangeAt`.                                                                                                 |
| `/api/notes/<NOTE>` | `PATCH`     | **Changes the permission, owner or URL of a note.**<br>The body must be a JSON object (`Content-Type: application/json`) with at least one of the fields `permission`, `owner` and `url`. The updated note is returned as an entry of the listing above. `<NOTE>` is the `id` or the `url` of the note. |

### Listing entries
- `id`: internal id of the note.
- `url`: path of the note relative to the server URL. This is the alias of the note if it has one, and its encoded id otherwise.
- `title`: title of the note, or `Untitled`.
- `tags`: tags read from the content of the note at each request.
- `permission`: one of `freely`, `editable`, `limited`, `locked`, `protected` and `private`.
- `owner`: Forgejo login of the owner, or `null`.
- `createdAt`, `lastchangeAt`: ISO 8601 dates.

```shell
curl -H "Authorization: Bearer $TOKEN" https://md.example.org/api/notes
```

```json
[
  {
    "id": "6b1f0c2e-8d4a-4b8e-9c3f-2a7d5e1f0b9c",
    "url": "meeting-notes",
    "title": "Meeting notes",
    "tags": ["aquila", "minutes"],
    "permission": "editable",
    "owner": "jdoe",
    "createdAt": "2026-01-12T09:30:00.000Z",
    "lastchangeAt": "2026-10-01T14:02:11.000Z"
  }
]
```

### Changing a note
The `PATCH` body accepts the following fields. Any other field is refused with HTTP 400.

- `permission`: new permission of the note. `freely` is refused when anonymous users may neither view nor edit notes.
- `owner`: Forgejo login of the new owner, compared case-insensitively. The user must have logged in at least once.
- `url`: new alias of the note. It may contain letters, digits and `.`, `_`, `~`, `-`, has at most 255 characters and must not start with a dot. It must not be a note id or a path used by the server. `null` or `""` removes the alias.

```shell
curl -X PATCH \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"permission": "locked", "owner": "jdoe", "url": "meeting-notes"}' \
     https://md.example.org/api/notes/6b1f0c2e-8d4a-4b8e-9c3f-2a7d5e1f0b9c
```

The changes are applied in the order `url`, `owner`, `permission`.
They are not transactional: if a later change fails, the earlier ones stay applied.
Editors in which the note is open are updated at once. When the URL changes, they reload the note at its new URL.

### Errors
Errors are returned as a JSON object `{"error": "<message>"}` with one of the following statuses.

| Status | Meaning                                                                                       |
| ------ | --------------------------------------------------------------------------------------------- |
| 400    | Invalid body: not a JSON object, empty, unknown field, invalid permission, owner or URL.      |
| 401    | Missing or wrong token.                                                                       |
| 404    | No token configured, or unknown note or user.                                                 |
| 409    | The URL is already used by another note or by a file in the documents directory.              |

## Personal notes API
These endpoints let a user script their own notes with the rights they have in the web interface.
They do not use the session cookie.
Each request must carry the header `Authorization: Bearer <TOKEN>`, where `<TOKEN>` is the user's personal API token.

### Getting a token
After logging in, click **API token** at the top of the main page.
The dialog generates a token, rotates it (the previous token stops working at once) or revokes it.
The token is shown only once, right after it is generated: the server stores only its SHA-256 hash.
A token is valid for 30 days after its generation. After that, requests get HTTP 401 with `{"error": "token expired"}` and a new token must be generated.
A token also stops working when its user may no longer log in, for example after leaving the organization.

The dialog uses these session endpoints, which accept only `Content-Type: application/json`:

| Endpoint        | HTTP-Method | Description                                                                                                            |
| --------------- | ----------- | ---------------------------------------------------------------------------------------------------------------------- |
| `/me/api-token` | `POST`      | **Generates or rotates the token.**<br>Returns `{"token", "createdAt", "expiresAt"}`. The token is not shown again.     |
| `/me/api-token` | `DELETE`    | **Revokes the token.**                                                                                                 |

`GET /me` reports the token state in the field `apiToken`: `null`, or `{"createdAt", "expiresAt", "lastUsedAt", "expired"}`.

### Endpoints
`<NOTE>` is the id, the url (alias or encoded id) or the short id of a note.

| Endpoint                            | HTTP-Method | Description                                                                                                                                                                                                                                                       |
| ----------------------------------- | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/api/v1/notes`                     | `GET`       | **Lists the user's notes.**<br>The notes the user owns and the notes in their history that they may view, most recently changed first, as entries like those of `/api/notes`, without content.                                                                    |
| `/api/v1/notes`                     | `POST`      | **Creates a note owned by the user.**<br>The body is the Markdown content (`Content-Type: text/markdown` or `text/plain`). `?url=<ALIAS>` gives the note an alias if [FreeURL-mode](../configuration.md#users-and-privileges) is enabled. Answers 201 with the entry, `Location` and `ETag`. |
| `/api/v1/notes/<NOTE>`              | `GET`       | **Returns the note.**<br>The entry with its `content` as JSON, or the raw Markdown with `Accept: text/markdown`. The `ETag` header identifies the content.                                                                                                      |
| `/api/v1/notes/<NOTE>/content`      | `PUT`       | **Replaces the content.**<br>The body is the new Markdown. `If-Match` is required: the `ETag` of the content being replaced, or `*` to overwrite whatever is there. Answers 204 with the new `ETag`.                                                              |
| `/api/v1/notes/<NOTE>/content/append` | `POST`    | **Appends to the content.**<br>The body is added on a new line at the end. No `If-Match` is needed. Answers 204 with the new `ETag`.                                                                                                                            |
| `/api/v1/notes/<NOTE>`              | `PATCH`     | **Changes the permission or the URL.**<br>JSON body with `permission` and/or `url` (`null` removes the alias). Owner or superuser only. A new alias requires FreeURL-mode.                                                                                     |
| `/api/v1/notes/<NOTE>`              | `DELETE`    | **Deletes the note.**<br>Owner or superuser only, and only for a note that has an owner. Editors showing the note are closed.                                                                                                                                  |

The view and edit rules are those of the web interface, superuser rights included.
A note the user may not view is reported as missing (404).
Changes to a note that is open in a browser reach its editors at once, like an edit by another user.
Carriage returns are removed from Markdown bodies.

```shell
TOKEN=hdt_...
SERVER=https://md.example.org

# create a note and read it back with its ETag
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: text/markdown" \
     --data-binary @minutes.md "$SERVER/api/v1/notes"
curl -i -H "Authorization: Bearer $TOKEN" -H "Accept: text/markdown" "$SERVER/api/v1/notes/<NOTE>"

# replace the content only if nobody changed it since the read
curl -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: text/markdown" \
     -H 'If-Match: "<ETAG>"' --data-binary @minutes.md "$SERVER/api/v1/notes/<NOTE>/content"

# append a line
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: text/plain" \
     --data-binary "- $(date -I): backup done" "$SERVER/api/v1/notes/<NOTE>/content/append"
```

Proxies that compress responses may turn the `ETag` into a weak one (`W/"..."`); `If-Match` accepts both forms.

### Personal API errors
Errors are returned as a JSON object `{"error": "<message>"}`.

| Status | Meaning                                                                                                   |
| ------ | --------------------------------------------------------------------------------------------------------- |
| 400    | Invalid JSON body, unknown field, invalid permission or URL.                                              |
| 401    | Missing, wrong, expired or revoked token, or the user may no longer log in.                               |
| 403    | The user may view the note but not do this, or FreeURL-mode is disabled.                                  |
| 404    | Unknown note, or a note the user may not view.                                                            |
| 409    | The URL is already used.                                                                                  |
| 412    | `If-Match` does not match the current content.                                                            |
| 413    | The content would exceed the maximum note length.                                                         |
| 415    | The body is not `text/markdown` or `text/plain`.                                                          |
| 428    | `PUT .../content` without `If-Match`.                                                                     |
| 503    | The access of the user could not be checked (for example, the login provider is unreachable). Retry later. |

## User / History
These endpoints return information about the current logged-in user and it's note history. If no user is logged-in, the most of this requests will fail with either a HTTP 403 or a JSON object containing `{"status":"forbidden"}`.

| Endpoint                 | HTTP-Method | Description                                                                                                                                                                                       |
| ------------------------ | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/me`                    | `GET`       | **Returns the profile data of the current logged-in user.**<br>The data is returned as a JSON object containing the user-id, the user's name and a url to the profile picture.                    |
| `/me/export`             | `GET`       | **Exports a zip-archive with all notes of the current user.**                                                                                                                                     |
| `/history`               | `GET`       | **Returns a list of the last viewed notes.**<br>The list is returned as a JSON object with an array containing for each entry it's id, title, tags, last visit time and pinned status.            |
| `/history`               | `POST`      | **Replace user's history with a new one.**<br>The body must be form-encoded and contain a field `history` with a JSON-encoded array like its returned from the server when exporting the history. |
| `/history?token=<TOKEN>` | `DELETE`    | **Deletes the user's history.**<br>Requires the user token since HedgeDoc 1.10.4 to prevent CSRF-attacks. The token can be obtained from the `/config` endpoint when logged-in.                   |
| `/history/<NOTE>`        | `POST`      | **Toggles the pinned status in the history for a note.**<br>The body must be form-encoded and contain a field `pinned` that is either `true` or `false`.                                          |
| `/history/<NOTE>`        | `DELETE`    | **Deletes a note from the user's history.**                                                                                                                                                       |

## HedgeDoc-server
These endpoints return information about the running HedgeDoc instance.

| Endpoint   | HTTP-Method | Description                                                                                                                                                                              |
| ---------- | ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/status`  | `GET`       | **Returns the current status of the HedgeDoc instance.**<br>The data is returned as a JSON object containing the number of notes stored on the server, (distinct) online users and more. |
| `/metrics` | `GET`       | **Prometheus-compatible endpoint**<br>Exposes the same stats as `/status` in addition to various Node.js performance figures. Available since HedgeDoc 1.8                               |
