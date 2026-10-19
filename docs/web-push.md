# Web Push

How the gateway delivers to browsers, how to run it with your own VAPID keys, and the browser behavior a web
client has to work with. The wire format is in [payload.md](payload.md#provider-mapping) and the endpoints in
[protocol.md](protocol.md).

## Contents

- [How it works](#how-it-works)
- [VAPID keys](#vapid-keys)
- [Client flow](#client-flow)
- [Browser support and quirks](#browser-support-and-quirks)
- [Permission prompts](#permission-prompts)
- [Local development](#local-development)

## How it works

1. The web client reads the app's `vapid_public_key` from discovery and calls `pushManager.subscribe()` with it.
   The browser returns an endpoint URL on its vendor's push service, plus `p256dh` and `auth`.
2. The client registers the **endpoint** with the gateway (`POST /v1/devices`, `platform: web`) and gives the
   instance `subscription_id`, `p256dh` and `auth`. The gateway never receives the keys.
3. The instance encrypts the notification to those keys (RFC 8291) and pushes it through the gateway.
4. The gateway signs a VAPID token (RFC 8292) for the push service and posts the ciphertext to the endpoint
   unchanged. The browser decrypts it and wakes the service worker.

The push service sees the ciphertext, its size, the `TTL`, `Urgency` and `Topic` headers, and the gateway's VAPID
key. It never sees content or which instance sent it.

## VAPID keys

Each app has one P-256 key pair. Browsers bind every subscription to the public key it was created with, so:

- **The public key is long lived.** Changing it invalidates every browser subscription of the app: pushes signed
  with the new key are refused (`401`/`403`, retried and then `provider_unavailable`) until each browser
  unsubscribes and subscribes again with the new key. Rotate only after a compromise, and ship a client that
  re-subscribes when discovery shows a new key.
- **The private key never leaves the gateway.** Keep it in a mounted secret (`web.vapid.private_key_file`).

Generate a pair with either tool:

```sh
npx web-push generate-vapid-keys
# Public Key:  B…   -> web.vapid_public_key
# Private Key: …    -> the contents of web.vapid.private_key_file

# or with OpenSSL (PEM private key):
openssl ecparam -name prime256v1 -genkey -noout -out vapid.pem
openssl ec -in vapid.pem -pubout -outform DER | tail -c 65 | base64 | tr '/+' '_-' | tr -d '=\n'
```

The gateway refuses to start when the private key does not match `vapid_public_key`.

`web.vapid.subject` is the `sub` claim, a `mailto:` or `https:` URL. Push services use it to contact the operator
about abuse or breaking changes, and Apple's service refuses tokens without it.

## Client flow

The web client (client plan Phase 7) should:

- **Subscribe once per service worker.** A browser has one push subscription per service worker registration, so
  the same endpoint and keys back the client's registration with every instance's gateway subscription. The
  plaintext's `instance` and `user_id` route each push to the right account.
- **Always pass `userVisibleOnly: true`** and **always show a notification** in the `push` handler, including
  when the payload cannot be parsed or routed (use a generic "New notification" with the instance name). Chrome
  shows its own "This site has been updated in the background" notice when a push shows nothing, and Safari
  revokes the subscription of a site whose pushes repeatedly show nothing.
- **Check the subscription on every start.** `pushManager.getSubscription()` can return a new endpoint, or
  `null` after the user cleared site data. `PUT /v1/devices/{id}` with the new endpoint, or subscribe and
  register again. Do not rely on the `pushsubscriptionchange` event; browsers fire it inconsistently.
- **Re-subscribe when the VAPID key changes.** Compare discovery's `vapid_public_key` with
  `subscription.options.applicationServerKey`. Subscribing with a new key requires `unsubscribe()` first.
- **Handle `gone` from the instance side.** When the browser unsubscribes or the subscription expires, the push
  service answers `404` or `410` and the gateway marks the subscription `gone`. The instance deletes its record; the
  client re-registers the next time it starts.
- **De-duplicate on `notification_id`** and use `tag` from the collapse key, since push services may deliver twice and
  not all of them honor `Topic`.

## Browser support and quirks

| Browser | Push service | Notes |
|---|---|---|
| Chrome, Edge (Chromium), Opera, Samsung Internet | `fcm.googleapis.com` (Edge: `*.notify.windows.com`) | Requires `userVisibleOnly: true`. No push in incognito windows. May use a quieter permission UI for sites whose prompts are often dismissed. |
| Brave | `fcm.googleapis.com` | Push is off by default: `subscribe()` fails until the user enables "Use Google services for push messaging". Tell the user how, rather than failing silently. |
| Firefox | `updates.push.services.mozilla.com` | No push in private windows. Permission prompts without a user gesture are suppressed to an icon in the address bar. |
| Safari on macOS 13+ | `web.push.apple.com` | Standard Web Push with VAPID; `sub` is required. Only `aes128gcm` bodies, which is all the gateway sends. |
| Safari on iOS and iPadOS 16.4+ | `web.push.apple.com` | **Only for web apps added to the Home Screen.** The site needs a web app manifest with `display: standalone` (or `fullscreen`), the user must add it to the Home Screen, and the permission request must come from a tap inside the installed app. A Safari tab cannot subscribe. Every push must show a notification. |

Common to all of them:

- **4 KB limit.** Push services accept at least 4,096 bytes of body. The gateway's 2,200-byte limit for the
  encrypted body keeps every push well inside it.
- **TTL.** Services may cap a long TTL. A push with `ttl: 0` is delivered only if the browser is reachable at once.
- **Urgency.** Browsers on battery may hold back `low` and `normal` pushes. Use `high` only for direct messages and
  mentions, as for native apps.
- **Endpoints identify a browser.** Only the holder of the app's VAPID private key can push to an endpoint, but the
  endpoint itself is a stable identifier of the browser. Clients send it only to the gateway, never to an instance.

## Permission prompts

Browsers punish sites that ask for notification permission at the wrong time, and a `denied` permission cannot be
asked for again from the page.

- Ask only in response to a user action, such as a "Turn on notifications" button in instance settings. Never
  prompt on page load. Safari on iOS and Firefox refuse or hide prompts that do not come from a gesture.
- Explain first with an in-app screen (what the user gets, per instance), then call
  `Notification.requestPermission()` when they agree. A dismissed browser prompt counts against the site.
- Handle all three states: `granted` (subscribe and register), `default` (offer the button again later) and
  `denied` (show how to re-enable notifications in the browser's site settings; the page cannot ask again).
- On iOS, show the "Add to Home Screen" instructions instead of the button when the app is not running standalone
  (`window.matchMedia('(display-mode: standalone)')`), because subscribing is impossible there.

## Local development

Browsers only talk to their vendors' push services, so local tests use the fake push service in
`internal/providers/providertest`, which verifies the VAPID token and decrypts each push like a browser. The
end-to-end stack runs it on the host and sets two development-only options in
[docker-compose.e2e.yml](../docker-compose.e2e.yml):

- `devices.web_push_hosts: [host.docker.internal]`, so endpoints on the fake are accepted, and
- `devices.web_push_allow_insecure: true`, so the gateway accepts `http` endpoints on any port and connects to
  private addresses.

Never enable `web_push_allow_insecure` in production. See [configuration.md](configuration.md#devices).
