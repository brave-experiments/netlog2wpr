// CSP seeding for wpr's replay-time script injection (see archive.mjs).

/** @typedef {import('./netlog/exchanges.mjs').Exchange} Exchange */
/** @typedef {import('./netlog/http-headers.mjs').HeaderEntry} HeaderEntry */

// CSP directive tokens as browsers read them: whitespace-separated, with
// case-insensitive names and keyword spellings (CSP spec). wpr's
// transformers.go splits values on literal spaces and matches lowercase
// prefixes, so values are normalized before any directive reasoning (see
// normalizeScriptDirective).
/** @param {string} directive @returns {string[]} */
const cspDirectiveTokens = (directive) => directive.trim().split(/\s+/).filter(Boolean)

/** @param {string} directive @returns {string} */
const cspDirectiveName = (directive) => cspDirectiveTokens(directive)[0]?.toLowerCase() ?? ''

// 'script-src' also prefix-matches script-src-elem/script-src-attr, exactly
// like wpr's HasPrefix(directive, "script-src") checks
/** @param {string} name @returns {boolean} */
const isScriptDirectiveName = (name) => name === 'default-src' || name.startsWith('script-src')

/** @param {string} directive @returns {boolean} */
const cspHasUnsafeInline = (directive) => cspDirectiveTokens(directive).some(token => token.toLowerCase() === "'unsafe-inline'")

// CSP3: a 'strict-dynamic' in the directive makes browsers ignore
// 'unsafe-inline' (and every allowlist source), so only a nonce or hash
// admits an inline script — 'unsafe-inline' alone grants nothing there
/** @param {string} directive @returns {boolean} */
const cspHasStrictDynamic = (directive) => cspDirectiveTokens(directive).some(token => token.toLowerCase() === "'strict-dynamic'")

/** @param {string} directive @returns {boolean} */
const admitsInlineScripts = (directive) => cspHasUnsafeInline(directive) && !cspHasStrictDynamic(directive)

/** @param {string} directive @returns {boolean} */
const cspHasSha = (directive) => cspDirectiveTokens(directive).some(token => /^'sha(?:256|384|512)-/i.test(token))

/** @param {string} directive @returns {boolean} */
const cspHasNonce = (directive) => cspDirectiveTokens(directive).some(token => /^'nonce-/i.test(token))

/**
 * Lowercases the spellings wpr pattern-matches in a script-governing
 * directive: its name ('script-src*' / 'default-src') and the keyword tokens
 * it compares against ('none', 'unsafe-inline', the 'nonce-' and
 * 'sha256-…' prefixes). Browsers read all of these case-insensitively while
 * wpr matches lowercase literals, so the normalized form is what wpr can
 * recognize (CSP keyword values like the nonce base64 keep their case). The
 * directive's leading/trailing whitespace is preserved.
 * @param {string} directive
 * @returns {string}
 */
const normalizeScriptDirective = (directive) => {
  const body = cspDirectiveTokens(directive).map((token, index) => {
    if (index === 0) return token.toLowerCase()
    if (/^'nonce-/i.test(token)) return `'nonce-${token.slice("'nonce-".length)}`
    if (/^'sha(?:256|384|512)-/i.test(token)) {
      const dash = token.indexOf('-')
      return token.slice(0, dash + 1).toLowerCase() + token.slice(dash + 1)
    }
    if (/^'(?:unsafe-inline|none)'$/i.test(token)) return token.toLowerCase()
    return token
  }).join(' ')
  return directive.slice(0, directive.length - directive.trimStart().length) + body +
    directive.slice(directive.trimEnd().length)
}

/**
 * Splits an enforced CSP value into its policies' directive lists. A value
 * may carry comma-separated policies, which browsers enforce as separate
 * policies while wpr's transformers treat the whole value as one
 * semicolon-split blob — a nonce on the first comma-policy would leave the
 * others blocking wpr's injected script. Each policy becomes its own header
 * entry, and within a policy whitespace runs collapse to single spaces
 * (browsers read any whitespace; wpr splits on literal ones).
 * @param {string} value
 * @returns {string[][]} one directive list per policy
 */
const parseCspPolicies = (value) => value.replace(/\s+/g, ' ').split(',')
  .map(policy => policy.split(';').filter(directive => directive.trim() !== ''))
  .filter(policy => policy.length > 0)
  .map(policy => policy.map(directive => isScriptDirectiveName(cspDirectiveName(directive))
    ? normalizeScriptDirective(directive)
    : directive))

/**
 * Seeds the enforced Content-Security-Policy headers of an HTML 200 exchange
 * with a fresh nonce so that wpr's replay-time script injection is
 * authorized without wpr relaxing the site's policy. Returns the (possibly
 * new) entries array; the input is never written to, and values already in
 * canonical form come back byte-identical.
 *
 * At replay, wpr injects deterministic.js into every archived HTML 200
 * response and rewrites the served CSP: its transformers pick the first
 * 'script-src'-prefixed directive of the first CSP header (falling back to
 * the header's last 'default-src') as both the nonce source for the injected
 * tag and the rewrite target, and a target carrying neither a nonce nor a
 * hash gets 'unsafe-inline' appended — un-blocking the site's own inline
 * scripts that the live site (and this recording) blocked. When the archived
 * headers instead carry a nonce on that directive, wpr copies it onto the
 * injected tag and leaves the policy intact, so only the injected script
 * gains permission and CSP-blocked site scripts stay blocked on both sides
 * of record/replay.
 *
 * The reasoning runs per policy on two directives:
 *
 * - the element directive governing wpr's <script> element, resolved along
 *   the script-src-elem → script-src → default-src fallback chain. A
 *   shadowed script-src never applies to elements, and script-src-attr only
 *   governs event handlers, so neither triggers seeding on its own.
 * - wpr's directive, which must both carry the nonce and govern the tag.
 *
 * Seeding is needed when some policy's element directive blocks the tag. It
 * is permission-neutral for the site: the added nonce matches nothing the
 * site ships, and a directive admitting inline scripts via 'unsafe-inline'
 * keeps its original bytes unless another enforced policy blocks arbitrary
 * inline scripts anyway (the conjunction already blocked them at record
 * time, and wpr then needs the nonce from the first script-governing
 * directive to tag its script). A 'strict-dynamic' directive is seeded even
 * when it carries 'unsafe-inline': under CSP3 browsers ignore that keyword
 * there, so the recorded policy blocks the tag, and the nonce is what admits
 * it — seeding revokes nothing and no mirrors are added.
 *
 * When no earlier policy carries a script-governing directive, the first
 * policy that does is promoted to the front of the rebuilt CSP header
 * entries (header order is insignificant to browsers, whose enforced
 * policies are conjoined, while wpr reads only the first header), so wpr
 * finds a nonce source for its tag.
 *
 * Seeding is permission-neutral for inline event handlers too: an attribute
 * directive admitting handlers is never seeded (the nonce would revoke its
 * 'unsafe-inline'), and a seeded directive that served as the handlers'
 * fallback (script-src, or default-src where the policy has no script-src)
 * has its original form copied verbatim into an explicit script-src-attr
 * appended to the policy. The same mirroring keeps a seeded default-src from
 * revoking recorded inline-style permissions through an explicit style-src.
 * The copies are a deliberate byte divergence from wpr record, which
 * archives neither. Since the appended attribute directive would otherwise
 * become wpr's nonce source without carrying a nonce, the element-governing
 * directive is moved ahead of it (or an explicit seeded script-src is
 * inserted before it) — directive order is insignificant to browsers.
 *
 * @param {Exchange} exchange
 * @param {string} nonce
 * @returns {HeaderEntry[]}
 */
const seedCspReplayNonce = (exchange, nonce) => {
  if (exchange.responseCode !== 200) return exchange.responseEntries
  const contentType = exchange.responseEntries.find(([name]) => name === 'Content-Type')
  if (contentType === undefined || !contentType[1].toLowerCase().startsWith('text/html')) return exchange.responseEntries
  /** @type {number[]} */
  const cspIndexes = []
  exchange.responseEntries.forEach(([name], index) => {
    if (name === 'Content-Security-Policy') cspIndexes.push(index)
  })
  if (cspIndexes.length === 0) return exchange.responseEntries

  const nonceToken = `'nonce-${nonce}'`
  /** @type {(directive: string) => boolean} */
  const hasOurNonce = (directive) => cspDirectiveTokens(directive).includes(nonceToken)
  // Mutable directive lists per enforced header, one per comma-separated policy
  const cspPolicies = cspIndexes.map(index => parseCspPolicies(/** @type {string} */ (exchange.responseEntries[index]?.[1])))

  // Comma-separated policies across all enforced headers, in order: each
  // becomes its own header entry at rebuild
  /** @type {{ directives: string[], entry: HeaderEntry }[]} */
  const policies = cspPolicies.flatMap((headerPolicies, cspIndex) => {
    const entry = /** @type {HeaderEntry} */ (exchange.responseEntries[/** @type {number} */ (cspIndexes[cspIndex])])
    return headerPolicies.map(directives => ({ directives, entry }))
  })

  // wpr reads only the first CSP header (Go's Header.Get): its nonce source
  // and rewrite target come from the first entry's wpr directive. When no
  // earlier policy carries a script-governing directive, the first one that
  // does takes over — and its header entry is promoted to the front of the
  // rebuilt entries below, so wpr reads it (header order is insignificant
  // to browsers, whose enforced policies are conjoined).
  /** @type {(directives: string[]) => number} */
  const wprDirectiveIndex = (directives) => {
    const script = directives.findIndex(directive => cspDirectiveName(directive).startsWith('script-src'))
    if (script !== -1) return script
    return directives.map(cspDirectiveName).lastIndexOf('default-src')
  }
  /** @type {{ directives: string[], index: number }|null} */
  let tagSource = null
  let tagSourcePolicyIndex = -1 // index into the flattened policies list
  for (const [policyIndex, policy] of policies.entries()) {
    const index = wprDirectiveIndex(policy.directives)
    if (index !== -1) {
      tagSource = { directives: policy.directives, index }
      tagSourcePolicyIndex = policyIndex
      break
    }
  }

  // The directive governing <script> elements: the script-src-elem →
  // script-src → default-src fallback chain (CSP effective-directive rules)
  /** @type {(directives: string[]) => number} */
  const elementDirectiveIndex = (directives) => {
    const names = directives.map(cspDirectiveName)
    for (const name of ['script-src-elem', 'script-src', 'default-src']) {
      const index = names.indexOf(name)
      if (index !== -1) return index
    }
    return -1
  }
  /** @type {(directives: string[], index: number) => boolean} */
  const isTagSource = (directives, index) =>
    tagSource !== null && directives === tagSource.directives && index === tagSource.index

  // Whether the directive admits wpr's injected <script> element. The tag
  // carries the tag source's own nonce (wpr copies the first nonce it finds)
  // or wpr's script hash (appended to its sha-carrying rewrite target), so
  // the tag source admits the tag through either; every other directive must
  // carry our replay nonce or admit arbitrary inline scripts.
  /** @type {(directives: string[], index: number) => boolean} */
  const admitsTag = (directives, index) => {
    const directive = /** @type {string} */ (directives[index])
    if (hasOurNonce(directive) || admitsInlineScripts(directive)) return true
    return isTagSource(directives, index) && (cspHasNonce(directive) || cspHasSha(directive))
  }

  /**
   * @param {{ directives: string[], index: number }} target
   */
  const seed = ({ directives, index }) => {
    const original = cspDirectiveTokens(/** @type {string} */ (directives[index]))
    const kept = original.filter(token => token.toLowerCase() !== "'none'")
    if (!kept.includes(nonceToken)) kept.splice(1, 0, nonceToken)
    directives[index] = kept.join(' ')
    // The added nonce makes browsers ignore 'unsafe-inline' in the seeded
    // directive, revoking the inline permissions it granted as a fallback.
    // Mirror the original into explicit sub-directives so the recorded
    // permissions survive: script-src-attr for event handlers and style-src
    // for inline styles. script-src-elem never governs either, so seeding it
    // adds no mirror; a directive that already carried a nonce or a hash had
    // its 'unsafe-inline' ignored before seeding too, and so did one with
    // 'strict-dynamic' (CSP3 ignores 'unsafe-inline' there), so neither
    // revokes anything.
    const revokesUnsafeInline = cspHasUnsafeInline(original.join(' ')) &&
      !cspHasNonce(original.join(' ')) && !cspHasSha(original.join(' ')) &&
      !cspHasStrictDynamic(original.join(' '))
    if (!revokesUnsafeInline) return
    const name = /** @type {string} */ (original[0]).toLowerCase()
    const names = directives.map(cspDirectiveName)
    if (name === 'default-src') {
      if (!names.includes('style-src')) directives.push(`style-src ${original.slice(1).join(' ')}`)
      if (!names.includes('script-src') && !names.includes('script-src-attr')) {
        directives.push(`script-src-attr ${original.slice(1).join(' ')}`)
      }
    } else if (name === 'script-src' && !names.includes('script-src-attr')) {
      directives.push(`script-src-attr ${original.slice(1).join(' ')}`)
    }
  }

  const needsSeed = cspPolicies.some(policies => policies.some(directives => {
    const index = elementDirectiveIndex(directives)
    return index !== -1 && !admitsTag(directives, index)
  }))

  if (needsSeed && tagSource !== null) {
    // Seeding the tag source puts our nonce first, so wpr tags its injected
    // script with it; the conjunction already blocked what it admits at
    // record time (needsSeed means some enforced policy blocks the tag). An
    // attribute directive admitting inline handlers is never seeded — the
    // nonce would revoke its 'unsafe-inline' — so the post-pass below moves
    // the element-governing directive ahead of it instead.
    const directive = /** @type {string} */ (tagSource.directives[tagSource.index])
    if (!(cspDirectiveName(directive) === 'script-src-attr' && cspHasUnsafeInline(directive))) {
      seed(tagSource)
    }
    // Every policy's element directive must admit the seeded tag: a foreign
    // nonce would block it (ours coexists with the site's), a blocking one
    // would be relaxed by wpr. Directives already admitting arbitrary inline
    // scripts are left alone — seeding would revoke that permission. A
    // 'strict-dynamic' directive is seeded: browsers ignore its
    // 'unsafe-inline', so the nonce is what admits the tag (CSP3 honors
    // nonces under 'strict-dynamic'), and nothing is revoked.
    cspPolicies.forEach(policies => policies.forEach(directives => {
      const index = elementDirectiveIndex(directives)
      if (index === -1) return
      const directive = /** @type {string} */ (directives[index])
      if (hasOurNonce(directive) || admitsInlineScripts(directive)) return
      seed({ directives, index })
    }))
  }

  // wpr's rewrite target — the first 'script-src'-prefixed directive, which
  // prefix-matches script-src-attr and shadowed script-src directives alike —
  // carrying neither a nonce, a hash nor 'unsafe-inline' would get
  // 'unsafe-inline' appended at replay. For an attribute target that
  // un-blocks handlers the recording had blocked (handler attributes can
  // never carry a nonce, so seeding keeps them blocked exactly as before);
  // for a script-src shadowed by a permissive script-src-elem it un-blocks
  // the handlers falling back to it, and seeding is permission-neutral there
  // ('self' coexists with the nonce, and the element directive still governs
  // elements). This runs whether or not needsSeed: when the element
  // directives already admit the tag, the rewrite target is the only thing
  // wpr would still relax. An element-governing target always carries our
  // nonce (needsSeed seeded it), admits the tag via 'unsafe-inline', or
  // carries a foreign nonce or hash — none are re-seeded here.
  cspPolicies.forEach(policies => policies.forEach(directives => {
    const index = wprDirectiveIndex(directives)
    if (index === -1) return
    const directive = /** @type {string} */ (directives[index])
    if (cspHasNonce(directive) || cspHasSha(directive) || admitsInlineScripts(directive)) return
    seed({ directives, index })
  }))

  // Make wpr's nonce source element-governing: after seeding, the first
  // 'script-src'-prefixed directive must carry our nonce for the tag to be
  // admitted, and an attribute directive never does (it only carries one
  // when seeded above, which never applies here). When a seeded element
  // directive is shadowed behind a nonce-less script-src-attr — a
  // pre-existing one admitting handlers, or the mirror appended by seed() —
  // move the element directive ahead of it, or insert an explicit seeded
  // script-src cloned from the seeded default-src where the policy has no
  // script-src of its own. Without this, wpr would read its nonce from the
  // attribute directive, find none, and its injected script would stay
  // blocked.
  cspPolicies.forEach(policies => policies.forEach(directives => {
    if (!directives.some(hasOurNonce)) return
    const first = directives.findIndex(directive => cspDirectiveName(directive).startsWith('script-src'))
    if (first === -1 || cspDirectiveName(/** @type {string} */ (directives[first])) !== 'script-src-attr') return
    if (hasOurNonce(/** @type {string} */ (directives[first]))) return
    const elem = elementDirectiveIndex(directives)
    if (elem === -1 || !hasOurNonce(/** @type {string} */ (directives[elem]))) return
    if (cspDirectiveName(/** @type {string} */ (directives[elem])) === 'default-src') {
      directives.splice(first, 0, `script-src ${cspDirectiveTokens(/** @type {string} */ (directives[elem])).slice(1).join(' ')}`)
    } else {
      const [elementDirective] = directives.splice(elem, 1)
      directives.splice(directives.findIndex(directive => cspDirectiveName(directive) === 'script-src-attr'), 0, /** @type {string} */ (elementDirective))
    }
  }))

  // Rebuild the entries: each comma-separated policy becomes its own header
  // entry, all other entries (and their tuples) are reused as-is. Untouched
  // values come back byte-identical. When the tag source is not the first
  // policy, its group is promoted ahead of the first CSP entry: header order
  // is insignificant to browsers (their enforced policies are conjoined),
  // but wpr reads only the first CSP header.
  const policyGroups = policies.map(policy =>
    /** @type {HeaderEntry} */ ([policy.entry[0], policy.directives.join(';')]))
  // First flattened policy index of each enforced header entry
  /** @type {number[]} */
  const policyOffsets = []
  let policyCursor = 0
  for (const headerPolicies of cspPolicies) {
    policyOffsets.push(policyCursor)
    policyCursor += headerPolicies.length
  }
  const promotedIndex = tagSourcePolicyIndex > 0 ? tagSourcePolicyIndex : -1
  /** @type {HeaderEntry[]} */
  const rebuilt = []
  exchange.responseEntries.forEach((entry, index) => {
    const cspIndex = cspIndexes.indexOf(index)
    if (cspIndex === -1) {
      rebuilt.push(entry)
      return
    }
    if (cspIndex === 0 && promotedIndex !== -1) {
      rebuilt.push(/** @type {HeaderEntry} */ (policyGroups[promotedIndex]))
    }
    const start = /** @type {number} */ (policyOffsets[cspIndex])
    const end = cspIndex + 1 < policyOffsets.length
      ? /** @type {number} */ (policyOffsets[cspIndex + 1])
      : policyCursor
    for (let group = start; group < end; group++) {
      if (group === promotedIndex) continue
      rebuilt.push(/** @type {HeaderEntry} */ (policyGroups[group]))
    }
  })
  const unchanged = rebuilt.length === exchange.responseEntries.length && rebuilt.every((entry, index) => {
    const original = exchange.responseEntries[index]
    return entry === original || (original !== undefined && entry[0] === original[0] && entry[1] === original[1])
  })
  return unchanged ? exchange.responseEntries : rebuilt
}

export { seedCspReplayNonce }
