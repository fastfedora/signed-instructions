"""The two pages of the local signing app. Plain HTML with inline script and
no external resources: the page is the what-you-see-is-what-you-sign
surface, so it shows the canonical text and the terms and nothing else."""
from __future__ import annotations

import html

_STYLE = """
  body { font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #1a1a1a;
         background: #fafafa; margin: 0; padding: 2rem 1rem; }
  main { max-width: 42rem; margin: 0 auto; background: #fff; border: 1px solid #ddd; border-radius: 8px;
         padding: 1.5rem 2rem; }
  h1 { font-size: 1.25rem; margin: 0 0 1rem; }
  pre { font: 15px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; white-space: pre-wrap;
        word-break: break-word; background: #f4f4f4; border: 1px solid #ddd; border-radius: 6px; padding: 1rem; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.25rem 1rem; margin: 1rem 0; }
  dt { color: #555; } dd { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  button { font: inherit; font-weight: 600; padding: 0.6rem 1.4rem; border-radius: 6px; border: 1px solid #0b57d0;
           background: #0b57d0; color: #fff; cursor: pointer; }
  button:disabled { opacity: 0.5; cursor: default; }
  button.secondary { background: #fff; color: #1a1a1a; border-color: #bbb; margin-left: 0.5rem; }
  #status { margin-top: 1rem; min-height: 1.5rem; }
  .ok { color: #137333; } .err { color: #b3261e; } .warn { color: #8a5a00; }
  .note { color: #555; font-size: 0.9rem; }
  .action { margin: 1rem 0 0.25rem; }
  .action strong { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
                   word-break: break-all; }
  .code { font-size: 1.1rem; margin: 1rem 0 0.25rem; }
  .code strong { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
                 letter-spacing: 0.2em; font-size: 1.4rem; }
"""

_SCRIPT = """
  const b64u = {
    dec: s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); s += '='.repeat((4 - s.length % 4) % 4);
                const bin = atob(s); const out = new Uint8Array(bin.length);
                for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out.buffer; },
    enc: buf => { const b = new Uint8Array(buf); let s = ''; for (const x of b) s += String.fromCharCode(x);
                  return btoa(s).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, ''); }
  };
  const status = (cls, text) => { const el = document.getElementById('status'); el.className = cls; el.textContent = text; };
  async function post(path, body) {
    const r = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' },
                                  body: body === undefined ? null : JSON.stringify(body) });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || data.detail || ('HTTP ' + r.status));
    return data;
  }
  // Whether the command has been given an answer, of any kind. Once it has, the
  // request token is spent and there is nothing left to decline.
  let settled = false;
  // A failure in the browser (cancelled prompt, authenticator refusal) ends the CLI's wait now.
  async function abort(kind, token, e) {
    settled = true;
    const msg = (e && e.message) || String(e);
    try { await post(`/api/${kind}/${token}/abort`, { error: msg }); } catch (_) {}
    status('err', (kind === 'enroll' ? 'Enrollment' : 'Signing') + ' failed: ' + msg + ' Run the command again to retry.');
  }
  // Closing the page is the most natural way to say no, so it has to mean no.
  // Without this the command would sit through its whole timeout waiting for an
  // answer that is never coming. sendBeacon rather than fetch: a page being torn
  // down is not guaranteed to finish an ordinary request, while a beacon is
  // handed to the browser to deliver after the page is gone.
  function declineOnClose(kind, token) {
    addEventListener('pagehide', () => {
      if (settled) return;
      navigator.sendBeacon(`/api/${kind}/${token}/abort`,
        new Blob([JSON.stringify({ error: 'the page was closed without signing' })],
                 { type: 'application/json' }));
    });
  }
"""


def _page(title: str, body: str, script: str) -> str:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title><style>{_STYLE}</style></head>
<body><main>{body}<div id="status"></div></main>
<script>{_SCRIPT}{script}</script></body></html>"""


def enroll_page(token: str, signer: str) -> str:
    body = f"""
<h1>Enroll a passkey for {html.escape(signer)}</h1>
<p>Your browser will ask you to create a passkey on this computer and verify it is you (Touch ID, Windows
Hello, or your security key). The passkey's public key is recorded in the signer registry under
<code>{html.escape(signer)}</code>; the private key never leaves the authenticator.</p>
<button id="go">Enroll with user verification</button>
<p class="note">Request <code>{html.escape(token[:8])}…</code>. This page works once; close it afterwards.</p>"""
    script = f"""
  const TOKEN = {token!r};
  document.getElementById('go').onclick = async () => {{
    const btn = document.getElementById('go'); btn.disabled = true; status('', 'Waiting for the authenticator…');
    try {{
      const opts = await post(`/api/enroll/${{TOKEN}}/options`);
      opts.challenge = b64u.dec(opts.challenge); opts.user.id = b64u.dec(opts.user.id);
      (opts.excludeCredentials || []).forEach(c => c.id = b64u.dec(c.id));
      opts.extensions = Object.assign({{ uvm: true }}, opts.extensions || {{}});
      const cred = await navigator.credentials.create({{ publicKey: opts }});
      const body = {{ id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type,
        clientExtensionResults: cred.getClientExtensionResults(),
        response: {{ clientDataJSON: b64u.enc(cred.response.clientDataJSON),
                    attestationObject: b64u.enc(cred.response.attestationObject),
                    transports: cred.response.getTransports ? cred.response.getTransports() : [] }} }};
      if (cred.authenticatorAttachment) body.authenticatorAttachment = cred.authenticatorAttachment;
      const res = await post(`/api/enroll/${{TOKEN}}/finish`, body);
      let msg = `Enrolled. Authenticator ${{res.aaguid}}` + (res.aaguid_label ? ` (${{res.aaguid_label}})` : '')
              + `, attestation ${{res.attestation_format}}` + (res.attestation_verified ? ', verified' : ', not verified')
              + '. Return to the terminal; you can close this tab.';
      status(res.aaguid_allowed ? 'ok' : 'warn', msg + (res.aaguid_allowed ? '' :
             ' This authenticator is not on the biometric-capable allowlist; blocks it signs will fail with authenticator_not_allowed.'));
    }} catch (e) {{ await abort('enroll', TOKEN, e); }}
  }};"""
    return _page("Enroll passkey", body, script)


def sign_page(token: str, payload: dict) -> str:
    """The terms the signer approves: the canonical text, the header fields, what
    the CLI will do with the signed block, and the confirmation code.

    This page is where approval happens. The terminal prints the same terms, but
    it does not ask: it cannot, wherever the command was started by something
    that owns the keyboard and leaves no controlling terminal behind -- an agent
    harness's shell escape, for one. So everything that carries authority has to
    be here, the destination included, and declining is closing the page or
    dismissing the authenticator.
    """
    rows = [("Signer", payload["signer"]), ("Key", payload["kid"]), ("Expires", payload["exp"] or "never (valid until removed)"),
            ("Audience", payload.get("aud") or "any"), ("Nonce", payload["jti"])]
    dl = "".join(f"<dt>{html.escape(k)}</dt><dd>{html.escape(v)}</dd>" for k, v in rows)
    action = (f"""
<p class="action">On signing: <strong>{html.escape(payload["action"])}</strong></p>
<p class="note">What a block authorizes depends on the file an agent reads it from, so this is part of
what you are approving. Cancel if it is not where you meant the instruction to go.</p>"""
              if payload.get("action") else "")
    body = f"""
<h1>Sign this instruction</h1>
<pre>{html.escape(payload["ctext"])}</pre>
<dl>{dl}</dl>{action}
<p class="code">Confirmation code <strong>{html.escape(payload["code"])}</strong></p>
<p class="note">Your terminal printed this code when you ran <code>sib sign</code>. If it does not
match, cancel: the ceremony you are being asked to approve is not the one you started.</p>
<button id="go">Sign with user verification</button>
<button id="no" class="secondary">Cancel</button>"""
    script = f"""
  const TOKEN = {token!r};
  declineOnClose('sign', TOKEN);
  const freeze = () => ['go', 'no'].forEach(id => document.getElementById(id).disabled = true);
  // An explicit no, which the command reports and acts on at once rather than
  // leaving the signer to guess whether walking away was enough.
  document.getElementById('no').onclick = async () => {{
    settled = true; freeze(); status('', 'Cancelling…');
    try {{ await post(`/api/sign/${{TOKEN}}/abort`, {{ error: 'cancelled on the sign page' }}); }} catch (_) {{}}
    status('err', 'Not signed. Nothing was written. You can close this tab.');
  }};
  document.getElementById('go').onclick = async () => {{
    freeze(); status('', 'Waiting for the authenticator…');
    try {{
      const opts = await post(`/api/sign/${{TOKEN}}/options`);
      opts.challenge = b64u.dec(opts.challenge);
      (opts.allowCredentials || []).forEach(c => c.id = b64u.dec(c.id));
      opts.extensions = Object.assign({{ uvm: true }}, opts.extensions || {{}});
      const cred = await navigator.credentials.get({{ publicKey: opts }});
      const body = {{ id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type,
        clientExtensionResults: cred.getClientExtensionResults(),
        response: {{ clientDataJSON: b64u.enc(cred.response.clientDataJSON),
                    authenticatorData: b64u.enc(cred.response.authenticatorData),
                    signature: b64u.enc(cred.response.signature),
                    userHandle: cred.response.userHandle ? b64u.enc(cred.response.userHandle) : null }} }};
      const res = await post(`/api/sign/${{TOKEN}}/finish`, body);
      settled = true;
      if (res.status === 'verified') status('ok', 'Signed and verified. Return to the terminal; you can close this tab.');
      else status('err', `The assertion did not verify: ${{res.status}} (${{res.error}}). The terminal has the details.`);
    }} catch (e) {{ await abort('sign', TOKEN, e); }}
  }};"""
    return _page("Sign instruction", body, script)
