# NXTL Shield private message server

This is the small open-source server behind private links in [NXTL Shield](https://nxtlsim.github.io/nxtl-shield/).

People write a short message in Shield. Their browser locks the text before anything is sent here. This server stores only that locked text. It deletes the text when someone opens the link, or when the time limit runs out (1 hour, 1 day, or 7 days). The secret needed to read the message stays in the link on the person's device. It is never sent here.

The service does not keep message text it can read, and it does not keep IP addresses.

## Use it

Open [NXTL Shield](https://nxtlsim.github.io/nxtl-shield/) and go to Messages. Create a private link there.

## For developers

The browser talks to this host:

`https://nxtl-shield-relay.dagys-mantas.workers.dev`

- `POST /v1/messages` with `{ "ciphertext": "<base64>", "ttl": 3600 | 86400 | 604800, "password": false }` returns `{ "id": "<id>" }`.
- `POST /v1/messages/:id/open` returns `{ "ciphertext": "<base64>", "password": false }` once, then deletes the stored text. A second call returns `404` with `{ "state": "gone" }`. Use POST, not GET, so a preview or scanner cannot open the message by fetching the link.
- `GET` or `HEAD /v1/messages/:id/status` returns `204` if the message is still waiting, or `404` with `{ "state": "gone" }`. It never returns the text.

`ttl` is 1 hour, 1 day, or 7 days, in seconds. The locked text may be at most 64 KB. `password` is an optional flag that a password was used in the browser; this server never receives the password or the secret key.

To run a local copy:

```
npm ci
npm test
npm run dev
```

## License

GNU General Public License v3.0 only. See [LICENSE](LICENSE).
