const Base = require('./base');
const qs = require('querystring');
const request = require('request-promise-native');
const jwt = require('jsonwebtoken');

const OAUTH_URL = 'https://graph.qq.com/oauth2.0/authorize';
const ACCESS_TOKEN_URL = 'https://graph.qq.com/oauth2.0/token';
const TOKEN_INFO_URL = 'https://graph.qq.com/oauth2.0/me';
const USER_INFO_URL = 'https://graph.qq.com/user/get_user_info';

const { QQ_ID, QQ_SECRET } = process.env;

module.exports = class extends Base {
  static check() {
    return QQ_ID && QQ_SECRET;
  }

  static info() {
    return { origin: new URL(OAUTH_URL).hostname };
  }

  redirect() {
    const { redirect, state } = this.ctx.params;
    const redirectUrl = this.getCompleteUrl('/qq') + '?' + qs.stringify({ redirect, state });

    const url = OAUTH_URL + '?' + qs.stringify({
      client_id: QQ_ID,
      redirect_uri: redirectUrl,
      response_type: 'code'
    });
    return this.ctx.redirect(url);
  }

  async indexAction() {
    const { code, redirect, state } = this.ctx.params;
    if (!code) {
      return this.redirect();
    }

    // Step 1: Exchange code for access token
    const tokenResponse = await this.getAccessToken(code);

    // Step 2: Fetch user info
    const user = await this.getUserInfoByToken(tokenResponse);

    // Step 3: Check or create DB record
    const userByQQ = await this.modelInstance.select({ qq: user.id });
    let objectId;
    if (!think.isEmpty(userByQQ)) {
      objectId = userByQQ[0].objectId;
    } else {
      const created = await this.modelInstance.add({
        display_name: user.name,
        email: user.email,
        avatar: user.avatar,
        qq: user.id,
        password: this.hashPassword(Math.random()),
        type: 'guest',
      });
      objectId = created.objectId;
    }

    // Step 4: Issue JWT
    const token = jwt.sign(objectId, this.config('jwtKey'));

    // Step 5: Redirect with token
    if (redirect) {
      this.redirect(redirect + (redirect.includes('?') ? '&' : '?') + 'token=' + token);
    } else {
      this.success({ token });
    }
  }

  // keep getAccessToken and getUserInfoByToken as you already have
};
