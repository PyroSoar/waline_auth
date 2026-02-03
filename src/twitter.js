const Base = require('./base');
const crypto = require('crypto');
const qs = require('querystring');
const uuid = require('uuid');
const Storage = require('./utils/storage/leancloud');
const request = require('request-promise-native');

const AUTH_URL = 'https://twitter.com/i/oauth2/authorize';
const TOKEN_URL = 'https://api.twitter.com/2/oauth2/token';
const USER_INFO_URL = 'https://api.twitter.com/2/users/me';

// Waline 环境变量：TWITTER_ID = OAuth2 Client ID
const TWITTER_CLIENT_ID = process.env.TWITTER_ID;
// Waline 需要 TWITTER_SECRET 才会启用 provider（PKCE 不使用）
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

module.exports = class extends Base {
  // Waline 必须看到 TWITTER_ID + TWITTER_SECRET 才会初始化 provider
  static check() {
    return TWITTER_CLIENT_ID && TWITTER_CLIENT_SECRET;
  }

  static info() {
    return {
      origin: new URL(AUTH_URL).hostname
    };
  }

  constructor(ctx) {
    super(ctx);
    this._session = new Storage('twitter');
  }

  async redirect() {
    const { redirect, state } = this.ctx.params;

    // redirect_uri 必须固定，不能带 query
    const callbackUrl = this.getCompleteUrl('/twitter');

    const { verifier, challenge } = generatePKCE();
    const oauthState = uuid.v4().replace(/-/g, '');

    // 保存 PKCE verifier + redirect + 原始 state
    await this._session.set(
      `pkce:${oauthState}`,
      JSON.stringify({ verifier, redirect, state, callbackUrl })
    );

    const params = {
      response_type: 'code',
      client_id: TWITTER_CLIENT_ID,
      redirect_uri: callbackUrl,
      scope: [
        'tweet.read',
        'users.read',
        'offline.access',
        'email'
      ].join(' '),
      state: oauthState,
      code_challenge: challenge,
      code_challenge_method: 'S256'
    };

    return this.ctx.redirect(AUTH_URL + '?' + qs.stringify(params));
  }

  async getAccessToken({ code, oauthState }) {
    const sessionRaw = await this._session.get(`pkce:${oauthState}`);
    if (!sessionRaw) return null;

    const { verifier, callbackUrl } = JSON.parse(sessionRaw);

    return await request({
      url: TOKEN_URL,
      method: 'POST',
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
    const { code, state: oauthState } = this.ctx.params;

    // 初次进入，没有 code/state，则发起 OAuth 2.0 授权
    if (!code || !oauthState) {
      return this.redirect();
    }

    this.ctx.type = 'json';

    const sessionRaw = await this._session.get(`pkce:${oauthState}`);
    if (!sessionRaw) {
      this.ctx.status = 400;
      return this.ctx.body = { error: 'Invalid OAuth state' };
    }

    const { redirect, state } = JSON.parse(sessionRaw);

    // 浏览器端先跳回 redirect，再由 Waline 服务端来拿用户信息
    if (redirect && this.ctx.headers['user-agent'] !== '@waline') {
      return this.ctx.redirect(
        redirect +
        (redirect.includes('?') ? '&' : '?') +
        qs.stringify({ code, state: oauthState })
      );
    }

    const tokenInfo = await this.getAccessToken({ code, oauthState });
    if (!tokenInfo || !tokenInfo.access_token) {
      this.ctx.status = 401;
      return this.ctx.body = { error: 'Failed to obtain access token from Twitter OAuth 2.0' };
    }

    const userInfo = await this.getUserInfoByToken(tokenInfo.access_token);
    const u = userInfo && userInfo.data ? userInfo.data : {};

    return this.ctx.body = {
      id: u.id,
      name: u.name || u.username,
      email: u.email || null,
      url: u.url || (u.username ? `https://twitter.com/${u.username}` : null),
      avatar: u.profile_image_url
    };
  }
};
