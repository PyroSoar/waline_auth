const Base = require('./base');
const qs = require('querystring');
const request = require('request-promise-native');

const OAUTH_URL = 'https://oauth-login.cloud.huawei.com/oauth2/v3/authorize';
const ACCESS_TOKEN_URL = 'https://oauth-login.cloud.huawei.com/oauth2/v3/token';
const USER_INFO_URL = 'https://oauth-login.cloud.huawei.com/oauth2/v3/userinfo';

const { HUAWEI_ID, HUAWEI_SECRET } = process.env;

module.exports = class extends Base {

  static check() {
    return HUAWEI_ID && HUAWEI_SECRET;
  }

  static info() {
    return {
      origin: new URL(OAUTH_URL).hostname
    };
  }

  async getAccessToken(code) {

    const { redirect, state } = this.ctx.params;

    const redirectUrl =
      this.getCompleteUrl('/huawei') +
      '?' +
      qs.stringify({ redirect, state });

    return request.post({
      url: ACCESS_TOKEN_URL,
      form: {
        grant_type: 'authorization_code',
        client_id: HUAWEI_ID,
        client_secret: HUAWEI_SECRET,
        code,
        redirect_uri: redirectUrl
      },
      json: true
    });
  }

  async getUserInfoByToken({ access_token }) {

    const userInfo = await request.get({
      url: USER_INFO_URL,
      headers: {
        Authorization: `Bearer ${access_token}`
      },
      json: true
    });

    /**
     * Huawei returns OpenID Connect standard fields:
     * sub
     * name
     * picture
     * email
     */

    return this.formatUserResponse({
      id: userInfo.sub,
      name: userInfo.name || userInfo.sub,
      email: userInfo.email,
      avatar: userInfo.picture,
      url: undefined
    }, 'huawei');
  }

  async redirect() {

    const { redirect, state } = this.ctx.params;

    const redirectUrl =
      this.getCompleteUrl('/huawei') +
      '?' +
      qs.stringify({ redirect, state });

    const url =
      OAUTH_URL +
      '?' +
      qs.stringify({
        client_id: HUAWEI_ID,
        redirect_uri: redirectUrl,
        response_type: 'code',
        scope: 'openid profile email'
      });

    return this.ctx.redirect(url);
  }
};