// mdlite.js - XSS-safe markdown->HTML renderer (self-hosted, no dependencies)
// Security: HTML entities are escaped FIRST, then only a whitelist of transforms applied.
// No raw HTML passthrough.
(function (root) {
  'use strict';

  function escHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // Sanitize href: only http://, https://, or relative paths starting with /
  function safeHref(href) {
    var h = (href || '').trim();
    if (/^https?:\/\//i.test(h)) return h;
    if (h.charAt(0) === '/') return h;
    return null; // drop unsafe href, keep link text
  }

  function mdlite(text) {
    if (typeof text !== 'string') return '';

    // Split into blocks (double newlines = paragraph breaks)
    // Process fenced code blocks first (before escaping inline)
    var blocks = [];
    var remaining = text;

    // Extract fenced code blocks before any other processing
    // We'll use placeholders to protect them from inline transforms
    var codeBlocks = [];
    remaining = remaining.replace(/```([^\n]*)\n([\s\S]*?)```/g, function (_, lang, code) {
      var idx = codeBlocks.length;
      // Escape HTML in the raw code content
      codeBlocks.push('<pre><code>' + escHtml(code.replace(/\n$/, '')) + '</code></pre>');
      return '\x00CODE' + idx + '\x00';
    });

    // Now split into lines for block-level processing
    var lines = remaining.split('\n');
    var output = [];
    var i = 0;

    while (i < lines.length) {
      var line = lines[i];

      // Code block placeholder
      if (/^\x00CODE\d+\x00$/.test(line.trim())) {
        var cidx = parseInt(line.trim().replace(/\x00CODE(\d+)\x00/, '$1'), 10);
        output.push(codeBlocks[cidx]);
        i++;
        continue;
      }

      // Headings (h1-h3 only)
      var hm = line.match(/^(#{1,3})\s+(.+)$/);
      if (hm) {
        var hlevel = hm[1].length;
        output.push('<h' + hlevel + '>' + inlineTransform(hm[2]) + '</h' + hlevel + '>');
        i++;
        continue;
      }

      // Unordered list
      if (/^[-*+]\s+/.test(line)) {
        var ulItems = [];
        while (i < lines.length && /^[-*+]\s+/.test(lines[i])) {
          ulItems.push('<li>' + inlineTransform(lines[i].replace(/^[-*+]\s+/, '')) + '</li>');
          i++;
        }
        output.push('<ul>' + ulItems.join('') + '</ul>');
        continue;
      }

      // Ordered list
      if (/^\d+\.\s+/.test(line)) {
        var olItems = [];
        while (i < lines.length && /^\d+\.\s+/.test(lines[i])) {
          olItems.push('<li>' + inlineTransform(lines[i].replace(/^\d+\.\s+/, '')) + '</li>');
          i++;
        }
        output.push('<ol>' + olItems.join('') + '</ol>');
        continue;
      }

      // Blank line - skip (paragraph separation)
      if (line.trim() === '') {
        i++;
        continue;
      }

      // Paragraph: accumulate consecutive non-special lines
      var paraLines = [];
      while (
        i < lines.length &&
        lines[i].trim() !== '' &&
        !/^#{1,3}\s/.test(lines[i]) &&
        !/^[-*+]\s+/.test(lines[i]) &&
        !/^\d+\.\s+/.test(lines[i]) &&
        !/^\x00CODE\d+\x00$/.test(lines[i].trim())
      ) {
        paraLines.push(inlineTransform(lines[i]));
        i++;
      }
      if (paraLines.length) {
        output.push('<p>' + paraLines.join('<br>') + '</p>');
      }
    }

    return output.join('\n');
  }

  function inlineTransform(s) {
    // s is raw text (not yet escaped); escape first, then apply inline transforms
    var t = escHtml(s);

    // Inline code (backtick) - protect from further transforms
    var inlineCodes = [];
    t = t.replace(/`([^`]+)`/g, function (_, code) {
      var idx = inlineCodes.length;
      // code is already HTML-escaped from escHtml above
      inlineCodes.push('<code>' + code + '</code>');
      return '\x01IC' + idx + '\x01';
    });

    // Bold (**text** or __text__)
    t = t.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    t = t.replace(/__([^_]+)__/g, '<strong>$1</strong>');

    // Italic (*text* or _text_) - single markers, not preceded/followed by same
    t = t.replace(/\*([^*]+)\*/g, '<em>$1</em>');
    t = t.replace(/_([^_]+)_/g, '<em>$1</em>');

    // Links [text](url) - href already HTML-escaped by escHtml, need to decode for check
    t = t.replace(/\[([^\]]*)\]\(([^)]*)\)/g, function (_, linkText, href) {
      // href was escaped by escHtml; decode &amp; back for the check then re-escape
      var rawHref = href.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'");
      var safe = safeHref(rawHref);
      if (!safe) return linkText; // drop link, keep text
      return '<a href="' + escHtml(safe) + '" target="_blank" rel="noopener noreferrer">' + linkText + '</a>';
    });

    // Restore inline codes
    inlineCodes.forEach(function (html, idx) {
      t = t.replace('\x01IC' + idx + '\x01', html);
    });

    return t;
  }

  root.mdlite = mdlite;
}(window));
