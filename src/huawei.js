const Base = require('./base');
const qs = require('querystring');
const request = require('request-promise-native');

const OAUTH_URL = 'https://oauth-login.cloud.huawei.com/oauth2/v3/authorize';
const ACCESS_TOKEN_URL = 'https://oauth-login.cloud.huawei.com/oauth2/v3/token';
const USER_INFO_URL = 'https://account.cloud.huawei.com/user/getUserInfo';

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

  /**
   * Step 1: exchange code -> access_token
   */
  async getAccessToken(code) {

    const redirect = this.ctx.params.redirect;
    const state = this.ctx.params.state;

    const redirectUrl =
      this.getCompleteUrl('/huawei') +
      '?' +
      qs.stringify({ redirect, state });

    const params = {
      grant_type: 'authorization_code',
      client_id: HUAWEI_ID,
      client_secret: HUAWEI_SECRET,
      code,
      redirect_uri: redirectUrl
    };

    return request.post({
      url: ACCESS_TOKEN_URL,
      form: params,
      json: true
    });
  }

  /**
   * Step 2: access_token -> user info
   */
  async getUserInfoByToken({ access_token }) {

    const userInfo = await request.get({
      url: USER_INFO_URL,
      headers: {
        Authorization: `Bearer ${access_token}`
      },
      json: true
    });

    /**
     * Huawei typical response:
     * {
     *   userId: "xxx",
     *   displayName: "xxx",
     *   email: "xxx",
     *   photoURL: "xxx"
     * }
     */

    return this.formatUserResponse({
      id: userInfo.userId,
      name: userInfo.displayName || userInfo.userId,
      email: userInfo.email || undefined,
      url: undefined,
      avatar: userInfo.photoURL
    }, 'huawei');
  }

  /**
   * Step 0: redirect to Huawei login
   */
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