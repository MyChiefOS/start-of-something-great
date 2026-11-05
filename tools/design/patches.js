// Production wiring the design leaves to the build: each entry is [design text, production text], applied once.
// Only behaviour goes here (a script the design marks with a placeholder, an id a script needs), never a change of
// look or wording without Aaron's yes.
'use strict';
const GISCUS = (term) => '<script src="https://giscus.app/client.js" data-repo="MyChiefOS/start-of-something-great" data-repo-id="R_kgDOVIbhKA" data-mapping="number" data-term="' + term + '" data-strict="0" data-reactions-enabled="1" data-emit-metadata="0" data-input-position="top" data-theme="preferred_color_scheme" data-lang="en" data-loading="lazy" crossorigin="anonymous" async></script>';
module.exports = {
  'talk.html': [
    // The design's replies card says "Replies load here through giscus."; giscus loads into that card.
    [/(<div class="card x[0-9a-f]{8}">)(<p class="fine x[0-9a-f]{8}">Replies load here through giscus\.<\/p>)/, '$1' + GISCUS('1') + '$2']
  ]
};
