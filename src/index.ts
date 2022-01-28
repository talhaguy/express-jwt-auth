import express, { RequestHandler } from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import { config } from 'dotenv';
import jwt from 'jsonwebtoken';

config({
  path: `.env.${process.env['NODE_ENV'] ?? 'development'}`,
});

const app = express();
app.use(bodyParser.json());
app.use(cookieParser());
app.use(
  cors({
    origin: process.env['ALLOWED_ORIGINS']?.split(',') ?? '*',
  })
);

const port = process.env['PORT'] ? parseInt(process.env['PORT'], 10) : 3000;

const onlyApplicationJson: RequestHandler = (req, res, next) => {
  const jsonHeader = req.header('Content-Type');

  if (jsonHeader !== 'application/json') {
    res.status(415);
    res.json({
      status: 'ERROR',
    });
    return;
  }

  next();
};

app.use(onlyApplicationJson);

const validateUsernamePasswordForm: RequestHandler = (req, res, next) => {
  let error = false;

  // TODO: better validation (e.g. no spaces)
  if (!req.body.username || req.body.username.trim().length === 0) {
    error = true;
  }

  if (!req.body.password || req.body.password.trim().length < 6) {
    error = true;
  }

  if (error) {
    res.status(400);
    res.json({
      status: 'ERROR',
    });
    return;
  }

  next();
};

// TODO: use real db
const FAKE_USER_DB: Record<string, any> = {
  'a@a.com': {
    username: 'a@a.com',
    password: 'asdfasdf',
  },
};
const FAKE_BLACKLISTED_TOKENS_DB: Record<string, any> = {};

const registerUser: RequestHandler = (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;

  if (FAKE_USER_DB[username]) {
    res.status(409);
    res.json({
      status: 'ERROR',
      message: 'User already exists',
    });
    return;
  }

  // TODO: hash password

  FAKE_USER_DB[username] = {
    username,
    password,
  };

  res.locals['user'] = {
    username,
  };

  next();
};

const authenticateUser: RequestHandler = (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;

  const user = FAKE_USER_DB[username];
  if (!user) {
    res.status(401);
    res.json({
      status: 'ERROR',
      message: 'No user exists',
    });
    return;
  }

  // TODO: unhash password
  const userPassword = user.password;
  if (password !== userPassword) {
    res.status(401);
    res.json({
      status: 'ERROR',
      message: 'Incorrect password',
    });
    return;
  }

  res.locals['user'] = {
    username,
  };

  next();
};

enum CookieName {
  AccessToken = 'accessToken',
  RefreshToken = 'refreshToken',
}

const authenticateAccessToken: RequestHandler = async (req, res, next) => {
  const token = req.cookies[CookieName.AccessToken];
  if (!token) {
    res.status(401);
    res.json({
      status: 'ERROR',
      message: 'Unauthorized access. No token found.',
    });
    return;
  }

  try {
    const payload = await verifyJWT<{ username: string }>(
      token,
      process.env['ACCESS_TOKEN_KEY'] ?? 'secret'
    );
    res.locals['user'] = {
      username: payload.username,
    };
    next();
  } catch (err) {
    res.status(401);
    res.json({
      status: 'ERROR',
      message: 'Unauthorized access. Verification of token failed.',
    });
    return;
  }
};

const authenticateRefreshToken: RequestHandler = async (req, res, next) => {
  const token = req.cookies[CookieName.RefreshToken];
  if (!token) {
    res.status(401);
    res.json({
      status: 'ERROR',
      message: 'Unauthorized access. No token found.',
    });
    return;
  }

  try {
    const payload = await verifyJWT<{ username: string }>(
      token,
      process.env['REFRESH_TOKEN_KEY'] ?? 'secret'
    );
    res.locals['user'] = {
      username: payload.username,
    };
    next();
  } catch (err) {
    res.status(401);
    res.json({
      status: 'ERROR',
      message: 'Unauthorized access. Verification of token failed.',
    });
    return;
  }
};

function createJWT(
  payload: { [key: string]: any },
  secret: string,
  expiresSeconds: number
): Promise<string> {
  return new Promise((res, rej) => {
    jwt.sign(
      payload,
      secret,
      {
        expiresIn: expiresSeconds,
      },
      (err, encoded) => {
        if (err) {
          rej(err);
          return;
        }

        if (!encoded) {
          rej(new Error('Could not encode'));
          return;
        }

        res(encoded);
      }
    );
  });
}

function verifyJWT<Payload = { [key: string]: any }>(
  encoded: string,
  secret: string
): Promise<Payload> {
  return new Promise((res, rej) => {
    jwt.verify(encoded, secret, (err, payload) => {
      if (err) {
        rej(err);
        return;
      }

      if (!payload || typeof payload === 'string') {
        rej(new Error('Incorrect payload'));
        return;
      }

      res(payload as Payload);
    });
  });
}

const ACCESS_TOKEN_EXPIRE_SECS = 15 * 60
const REFRESH_TOKEN_EXPIRE_SECS = 120 * 60

const addAccessAndRefreshToken: RequestHandler = async (req, res, next) => {
  const user = res.locals['user'];
  if (!user) {
    res.status(500);
    res.json({
      status: 'ERROR',
      message: 'Could not determine user',
    });
    return;
  }

  // if there's already tokens, blacklist them
  const oldAccessToken = req.cookies[CookieName.AccessToken];
  if (oldAccessToken) {
    FAKE_BLACKLISTED_TOKENS_DB[oldAccessToken];
  }
  const oldRefreshAccessToken = req.cookies[CookieName.RefreshToken];
  if (oldRefreshAccessToken) {
    FAKE_BLACKLISTED_TOKENS_DB[oldRefreshAccessToken];
  }

  try {
    const encodedAccessJWT = await createJWT(
      {
        username: user.username,
      },
      process.env['ACCESS_TOKEN_KEY'] ?? 'secret',
      ACCESS_TOKEN_EXPIRE_SECS
    );
    const encodedRefreshJWT = await createJWT(
      {
        username: user.username,
      },
      process.env['REFRESH_TOKEN_KEY'] ?? 'secret',
      REFRESH_TOKEN_EXPIRE_SECS
    );

    const now = new Date();
    const expireAccessToken = new Date(now.getTime() + ACCESS_TOKEN_EXPIRE_SECS * 1000);
    const expireRefreshToken = new Date(now.getTime() + REFRESH_TOKEN_EXPIRE_SECS * 1000);

    res.cookie(CookieName.AccessToken, encodedAccessJWT, {
      expires: expireAccessToken,
      httpOnly: true,
      sameSite: 'lax',
    });
    res.cookie(CookieName.RefreshToken, encodedRefreshJWT, {
      expires: expireRefreshToken,
      httpOnly: true,
      sameSite: 'lax',
    });

    next();
  } catch (err) {
    res.status(500);
    res.json({
      status: 'ERROR',
      message: 'Could not create token(s). Reason: ' + (err as Error).message,
    });
  }
};

app.post(
  '/register',
  validateUsernamePasswordForm,
  registerUser,
  addAccessAndRefreshToken,
  (_, res) => {
    res.json({
      status: 'SUCCESS',
      message: 'Registered user',
    });
  }
);

app.post(
  '/login',
  validateUsernamePasswordForm,
  authenticateUser,
  addAccessAndRefreshToken,
  (_, res) => {
    res.json({
      status: 'SUCCESS',
      message: 'Logged in',
    });
  }
);

app.post(
  '/refreshToken',
  authenticateRefreshToken,
  addAccessAndRefreshToken,
  (_, res) => {
    res.json({
      status: 'SUCCESS',
      message: 'Refreshed tokens',
    });
  }
);

const apiRouter = express.Router();

// TODO: remove sample auth route
apiRouter.get('/data', authenticateAccessToken, (_, res) => {
  res.json({
    status: 'SUCCESS',
    message: 'You can access this',
  });
});

app.use('/api', apiRouter);

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
