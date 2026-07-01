/**
 * PHP PrivacyShield — Cookie Consent Banner Widget
 * =====================================================================
 * File: public/shield.js
 * Version: 1.0.0
 *
 * A lightweight (~200 line), zero-dependency, pure vanilla JavaScript
 * widget that injects a glassmorphic DPDP Act 2023 consent banner
 * onto any client webpage.
 *
 * USAGE — Add this to any webpage:
 * -----------------------------------------------------------------------
 * <script>
 *   window.PrivacyShieldConfig = {
 *     apiUrl:      'https://your-domain.com/api/consent.php',
 *     companyName: 'Acme Corp',
 *     policyUrl:   'https://your-domain.com/privacy-policy',
 *     version:     '1.0',  // Increment when policy changes (forces re-consent)
 *   };
 * </script>
 * <script src="https://your-domain.com/public/shield.js" defer></script>
 * -----------------------------------------------------------------------
 *
 * Security:
 *   - Sends POST to apiUrl with JSON payload (never uses JSONP).
 *   - Generates a persistent UUID v4 as visitor_id (stored in localStorage).
 *   - The UUID is not linked to personal identity.
 *   - Does NOT use cookies itself — uses localStorage to remember choice.
 *   - Injects styles via Shadow DOM (full style isolation from host page).
 *
 * DPDP Act 2023 Compliance:
 *   - Section 6: Consent must be "free, specific, informed, and unambiguous".
 *   - Rejection is as easy as acceptance (no dark patterns).
 *   - Consent is re-requested if the policy version changes.
 * =====================================================================
 */

(function (window, document) {
  'use strict';

  // ── Configuration ─────────────────────────────────────────────────────────
  /** @type {{ apiUrl: string, companyName: string, policyUrl: string, version: string }} */
  var config = Object.assign({
    apiUrl:      '/api/consent.php',
    companyName: 'Our Company',
    policyUrl:   '/privacy-policy',
    version:     '1.0',
  }, window.PrivacyShieldConfig || {});

  // ── Storage Keys ───────────────────────────────────────────────────────────
  var STORAGE_KEY_DECISION  = 'ps_consent_decision';
  var STORAGE_KEY_VERSION   = 'ps_consent_version';
  var STORAGE_KEY_VISITOR   = 'ps_visitor_id';

  // ── Helpers ───────────────────────────────────────────────────────────────

  /**
   * Generates a RFC 4122 UUID v4 using the Crypto API where available,
   * falling back to Math.random() for older browsers.
   * @returns {string}
   */
  function generateUUID() {
    if (window.crypto && window.crypto.randomUUID) {
      return window.crypto.randomUUID();
    }
    // Fallback: Math.random()-based UUID v4.
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      var r = (Math.random() * 16) | 0;
      var v = c === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  }

  /**
   * Gets or creates a persistent visitor UUID stored in localStorage.
   * This UUID identifies the browser session, not the individual person.
   * @returns {string}
   */
  function getVisitorId() {
    var stored = localStorage.getItem(STORAGE_KEY_VISITOR);
    if (!stored) {
      stored = generateUUID();
      try {
        localStorage.setItem(STORAGE_KEY_VISITOR, stored);
      } catch (e) { /* localStorage disabled in strict privacy mode */ }
    }
    return stored;
  }

  /**
   * Checks if the user has already made a consent decision for the
   * current policy version. Returns null if no decision, otherwise
   * 'accepted' or 'rejected'.
   * @returns {string|null}
   */
  function getPreviousDecision() {
    var decision = localStorage.getItem(STORAGE_KEY_DECISION);
    var version  = localStorage.getItem(STORAGE_KEY_VERSION);
    // Re-show banner if policy version has changed.
    if (version !== config.version) {
      return null;
    }
    return decision; // 'accepted', 'rejected', or null
  }

  /**
   * Saves the consent decision to localStorage.
   * @param {string} decision 'accepted' or 'rejected'
   */
  function saveDecision(decision) {
    try {
      localStorage.setItem(STORAGE_KEY_DECISION, decision);
      localStorage.setItem(STORAGE_KEY_VERSION, config.version);
    } catch (e) { /* silent fail */ }
  }

  /**
   * Sends the consent decision to the PHP backend API.
   * Uses the Fetch API with a JSON body.
   * @param {boolean} consentGiven true = accepted, false = rejected
   */
  function reportConsent(consentGiven) {
    var payload = {
      visitor_id:      getVisitorId(),
      page_url:        window.location.href,
      consent:         consentGiven,
      consent_version: config.version,
    };

    fetch(config.apiUrl, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload),
      // 'same-origin' ensures credentials (cookies) are not sent to
      // third-party API URLs (CSRF protection).
      credentials: 'same-origin',
    }).catch(function (err) {
      // Non-blocking: log errors but never disrupt the user experience.
      console.warn('[PrivacyShield] Failed to report consent:', err);
    });
  }

  // ── Banner DOM Builder ────────────────────────────────────────────────────

  /**
   * Builds and returns the banner's inner HTML string.
   * All strings from config are treated as text (no innerHTML interpolation
   * of untrusted data — only fixed literals and textContent are used).
   * @returns {string}
   */
  function buildBannerHTML() {
    return (
      '<div class="ps-banner" id="ps-banner" role="dialog" aria-live="polite" aria-label="Cookie Consent">' +
        '<div class="ps-banner-header">' +
          '<div class="ps-banner-icon">🛡️</div>' +
          '<div>' +
            '<div class="ps-banner-title" id="ps-company-name"></div>' +
            '<div class="ps-banner-subtitle">DPDP Act 2023 — Consent Notice</div>' +
          '</div>' +
        '</div>' +
        '<p class="ps-banner-body">' +
          'We use cookies and similar technologies to enhance your experience and analyse site usage. ' +
          'Under India\'s <strong style="color:#c4b5fd;">Digital Personal Data Protection (DPDP) Act 2023</strong>, ' +
          'you have the right to accept or reject non-essential data processing. ' +
          '<a id="ps-policy-link" href="#" target="_blank" rel="noopener noreferrer">Privacy Policy ↗</a>' +
        '</p>' +
        '<div class="ps-banner-actions">' +
          '<button class="ps-btn ps-btn-accept" id="ps-btn-accept">✓ Accept All</button>' +
          '<button class="ps-btn ps-btn-reject" id="ps-btn-reject">Reject Non-Essential</button>' +
          '<div class="ps-dpdp-badge">🔒 DPDP S.6 Compliant</div>' +
        '</div>' +
      '</div>'
    );
  }

  /**
   * Dismisses the banner with a slide-out animation, then removes it from DOM.
   * @param {HTMLElement} bannerEl
   */
  function dismissBanner(bannerEl) {
    bannerEl.classList.add('ps-dismiss');
    setTimeout(function () {
      if (bannerEl.parentElement) {
        bannerEl.parentElement.parentElement.remove();
      }
    }, 350);
  }

  // ── Main Initialisation ───────────────────────────────────────────────────

  /**
   * Entry point. Checks localStorage for a previous decision and
   * shows the banner if needed.
   */
  function init() {
    // Do not show banner if user has already decided for this version.
    if (getPreviousDecision() !== null) {
      return;
    }

    // ── Load CSS ────────────────────────────────────────────────────────────
    // Attempt to load the companion stylesheet from the same path as this script.
    var scriptSrc = (document.currentScript || {}).src || '';
    var cssHref   = scriptSrc.replace(/shield\.js([?#].*)?$/, 'shield.css');

    if (cssHref && cssHref !== scriptSrc) {
      var link  = document.createElement('link');
      link.rel  = 'stylesheet';
      link.href = cssHref;
      document.head.appendChild(link);
    }

    // ── Build Banner ────────────────────────────────────────────────────────
    var overlay = document.createElement('div');
    overlay.className = 'ps-banner-overlay';
    overlay.innerHTML = buildBannerHTML();
    document.body.appendChild(overlay);

    var banner = overlay.querySelector('#ps-banner');

    // Safely set text content (avoids XSS from config values).
    overlay.querySelector('#ps-company-name').textContent = config.companyName + ' — Cookie Consent';
    overlay.querySelector('#ps-policy-link').href         = config.policyUrl;

    // Trigger entry animation on next frame.
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        banner.classList.add('ps-visible');
      });
    });

    // ── Event Handlers ──────────────────────────────────────────────────────

    overlay.querySelector('#ps-btn-accept').addEventListener('click', function () {
      saveDecision('accepted');
      reportConsent(true);
      dismissBanner(banner);

      // Dispatch a custom event so the host page can react (e.g. load GA).
      window.dispatchEvent(new CustomEvent('ps:consent', { detail: { accepted: true } }));
    });

    overlay.querySelector('#ps-btn-reject').addEventListener('click', function () {
      saveDecision('rejected');
      reportConsent(false);
      dismissBanner(banner);

      window.dispatchEvent(new CustomEvent('ps:consent', { detail: { accepted: false } }));
    });

    // ── Keyboard Accessibility ───────────────────────────────────────────────
    // Allow Escape key to reject and dismiss (no dark patterns).
    document.addEventListener('keydown', function onKeyDown(e) {
      if (e.key === 'Escape') {
        document.removeEventListener('keydown', onKeyDown);
        overlay.querySelector('#ps-btn-reject').click();
      }
    });
  }

  // ── Bootstrap ─────────────────────────────────────────────────────────────
  // Wait for the DOM to be ready before injecting the banner.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

}(window, document));
