import express from 'express';
import jwt from 'express-jwt';
import uuid from 'node-uuid';
import cookieParser from 'cookie-parser';
import jwtToken from 'jsonwebtoken';
import colors from 'colors';


const app = express();
const SECRET = 'foobar';
const COOKIE_NAME = 'mein-cookie';

class ETagStore {
  constructor() {
    this._data = {};
  }
  setToken(token) {
    let id = uuid.v1();
    this._data[id] = token;
    return id;
  }
  getToken(key) {
    return this._data[key];
  }
}

const eStore = new ETagStore();

app.use(cookieParser());

app.use(jwt({
  secret: SECRET,
  credentialsRequired: true,
  getToken: function fromHeaderOrQuerystring (req) {
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
        return req.headers.authorization.split(' ')[1];
    } else if (req.query && req.query.token) {
      return req.query.token;
    }
    return null;
  }
}).unless({path: ['/token', '/']}));

app.get('/token', (req, res) => {

  // console.log(req.headers, req.cookies);

  let tokenContent = null;
  let eTagKey = null;

  // try to get the tokenContent from the cookie
  if (req.cookies[COOKIE_NAME]) {
    try {
      tokenContent = jwtToken.verify(req.cookies[COOKIE_NAME], SECRET);
      console.log(`token verified from cookie: ${JSON.stringify(tokenContent)}`.green);
    } catch (err) {
      console.log(`Unable to verify ${req.cookies[COOKIE_NAME]}`.red);
    }
  }

  if (!tokenContent && req.headers['if-none-match']) {
    eTagKey = req.headers['if-none-match'];
    let t = eStore.getToken(eTagKey);
    if (t) {
      try {
        tokenContent = jwtToken.verify(t, SECRET);
        console.log(`token verified from etag: ${eTagKey} --> ${JSON.stringify(tokenContent)}`.green);
      }
      catch (err) {
        console.log(`Unable to verify ${req.headers.etag} --> ${t}`.red);
      }
    } else {
      console.log(`No ETag key in store`.yellow);
      eTagKey = null;
    }
  } else {
    if (tokenContent) {
      console.log(`No ETag needed`.green);
    } else {
      console.log(`No ETag detected`.yellow);
    }
  }

  if (!tokenContent) {
    console.log(`Unable to detect token, generating new one.`.green);
    tokenContent = {
      invoice: uuid.v4(),
    };
  }

  let token = jwtToken.sign(tokenContent, SECRET);

  // would need domain.
  console.log(`Setting cookie ${COOKIE_NAME}.`.blue);
  res.cookie(COOKIE_NAME, token, { expires: new Date(Date.now() + 5), httpOnly: true });

  // bad kitty
  if (!eTagKey) {
    eTagKey = eStore.setToken(token);
  }
  console.log(`Setting ETag to ${eTagKey}.`.blue);
  res.set('ETag', eTagKey);

  res.format({
    'application/json': () => {
      res.send({token: token});
    },
    'application/jwt': () => {
      res.send(token);
    },
    'default': () => {
      // log the request and respond with 406
      res.status(406).send('Not Acceptable');
    }
  });

});

app.get('/api-view', (req, res) => {
  res.json(req.user);
});

app.get('/iframe', (req, res) => {
  console.log(`Got request from ${JSON.stringify(req.user)}.`.green);
  res.sendFile(`${__dirname}/public/iframe.html`);
});

app.get('/', function(req, res) {
  res.sendFile(`${__dirname}/public/index.html`);
});

const server = app.listen(3100, () => {
  let host = server.address().address;
  let port = server.address().port;
  console.log(`App listening at http://${host}:${port}`);
});
