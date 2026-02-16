const Base = require('./base');
const crypto = require('crypto');
const qs = require('querystring');
const request = require('request-promise-native');

const AUTH_URL = 'https://x.com/i/oauth2/authorize';
const TOKEN_URL = 'https://api.x.com/2/oauth2/token';
const USER_INFO_URL = 'https://api.x.com/2/users/me';

const TWITTER_CLIENT_ID = process.env.TWITTER_ID;
const TWITTER_CLIENT_SECRET = process.env.TWITTER_SECRET;

// PKCE helpers
function base64url(buf) {
  return buf.toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function generatePKCE() {
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(
    crypto.createHash('sha256').update(verifier).digest()
  );
  return { verifier, challenge };
}

/**
 * Encode state data to base64 for stateless operation
 */
function encodeStateData(data) {
  return Buffer.from(JSON.stringify(data)).toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

/**
 * Decode state data from base64
 */
function decodeStateData(encoded) {
  try {
    const padded = encoded + '='.repeat((4 - encoded.length % 4) % 4);
    const decoded = Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString();
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

module.exports = class extends Base {
  static check() {
    return TWITTER_CLIENT_ID && TWITTER_CLIENT_SECRET;
  }

  static info() {
    return {
      origin: new URL(AUTH_URL).hostname
    };
  }

  async redirect() {
    const { redirect, state } = this.ctx.params;
    const callbackUrl = this.getCompleteUrl('/twitter');

    const { verifier, challenge } = generatePKCE();

    // Encode all necessary state data (PKCE verifier, redirect URL, original state)
    const stateData = encodeStateData({
      verifier,
      redirect,
      state,
      callbackUrl
    });

    const params = {
      response_type: 'code',
      client_id: TWITTER_CLIENT_ID,
      redirect_uri: callbackUrl,
      scope: [
        'tweet.read',
        'users.read',
        'offline.access',
        'users.email'
      ].join(' '),
      state: stateData,
      code_challenge: challenge,
      code_challenge_method: 'S256'
    };

    return this.ctx.redirect(AUTH_URL + '?' + qs.stringify(params));
  }

  async getAccessToken({ code, stateData }) {
    const { verifier, callbackUrl } = stateData;

    return await request({
      url: TOKEN_URL,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      form: {
        grant_type: 'authorization_code',
        client_id: TWITTER_CLIENT_ID,
        redirect_uri: callbackUrl,
        code,
        code_verifier: verifier
      },
      json: true
    });
  }



  async getUserInfoByToken(access_token) {
    const url = USER_INFO_URL +
      '?user.fields=name,username,profile_image_url,url,email';

    return await request({
      url,
      method: 'GET',
      headers: {
        Authorization: `Bearer ${access_token}`
      },
      json: true
    });
  }

  async getUserInfo() {
    const { code, state: encodedState } = this.ctx.params;

    // If no code/state, initiate OAuth 2.0 authorization
    if (!code || !encodedState) {
      return this.redirect();
    }

    this.ctx.type = 'json';

    // Decode the state to recover verifier and redirect info
    const stateData = decodeStateData(encodedState);
    if (!stateData) {
      this.ctx.status = 400;
      return this.ctx.body = { error: 'Invalid OAuth state' };
    }

    const { redirect } = stateData;

    // If a redirect URL was provided, forward the code/state back to that client
    if (redirect && this.ctx.headers['user-agent'] !== '@waline') {
      return this.ctx.redirect(
        redirect +
        (redirect.includes('?') ? '&' : '?') +
        qs.stringify({ code, state: encodedState })
      );
    }

    // Exchange the code for an access token using the verifier from stateData
    const tokenInfo = await this.getAccessToken({ code, stateData });
    if (!tokenInfo || !tokenInfo.access_token) {
      this.ctx.status = 401;
      return this.ctx.body = { error: 'Failed to obtain access token from Twitter OAuth 2.0' };
    }

    // Fetch user info with the access token
    const userInfo = await this.getUserInfoByToken(tokenInfo.access_token);
    const u = userInfo && userInfo.data ? userInfo.data : {};

    return this.ctx.body = this.formatUserResponse({
      id: u.id,
      name: u.name || u.username,
      email: u.email || undefined,
      url: u.url || (u.username ? `https://twitter.com/${u.username}` : undefined),
      avatar: u.profile_image_url || undefined
    }, 'twitter');
  }

};
