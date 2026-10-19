// @ts-check
import { defineConfig } from 'astro/config';

import tailwindcss from '@tailwindcss/vite';

import cloudflare from '@astrojs/cloudflare';

// https://astro.build/config
export default defineConfig({
  vite: {
    plugins: [tailwindcss()]
  },

  adapter: cloudflare({
    // We don't use Astro's image pipeline; a passthrough service avoids
    // provisioning an Images binding we don't need.
    imageService: 'passthrough'
  }),

  output: 'server',

  // We manage sessions ourselves with a D1-backed cookie, so we don't
  // need Astro's session KV namespace provisioned on deploy.
  session: false,

  // We do our own, more tolerant Origin check in middleware (and the
  // session cookie is SameSite=Lax). Astro's default check rejects
  // opaque origins ("null") and host aliases like 127.0.0.1 vs localhost.
  security: {
    checkOrigin: false
  }
});
