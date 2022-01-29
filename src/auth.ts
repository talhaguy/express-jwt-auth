import { RequestHandler } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import {
  ACCESS_TOKEN_EXPIRE_SECS,
  CookieName,
  REFRESH_TOKEN_EXPIRE_SECS,
} from './constants';
import { AuthDBFacade, User } from './authDB';

interface AuthHandlerDeps {
  authDBFacade: AuthDBFacade;
}

interface AuthHandlerFactoryFunc {
  (deps: AuthHandlerDeps): RequestHandler;
}

const emailRegExp =
  /^[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/;

const validateUsernamePasswordForm: RequestHandler = (req, res, next) => {
  let error = false;

  if (!emailRegExp.test(req.body.username)) {
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

const registerUser: AuthHandlerFactoryFunc =
  ({ authDBFacade }) =>
  async (req, res, next) => {
    const username = req.body.username;
    const password = req.body.password;

    // check for duplicate user
    try {
      const user = await authDBFacade.getUser(username);

      if (user) {
        res.status(409);
        res.json({
          status: 'ERROR',
          message: 'User already exists',
        });
        return;
      }
    } catch (err) {
      res.status(500);
      res.json({
        status: 'ERROR',
        message: 'Could not check for existing user',
      });
      return;
    }

    // hash password
    let hashedPassword: string;
    try {
      hashedPassword = await bcrypt.hash(password, 10);
    } catch (err) {
      res.status(500);
      res.json({
        status: 'ERROR',
        message: 'Error hashing password',
      });
      return;
    }

    // save user
    try {
      await authDBFacade.saveUser({
        username,
        password: hashedPassword,
      });

      res.locals['user'] = {
        username,
      };
    } catch (err) {
      res.status(500);
      res.json({
        status: 'ERROR',
        message: 'Error saving user',
      });
      return;
    }

    next();
  };

const authenticateUser: AuthHandlerFactoryFunc =
  ({ authDBFacade }) =>
  async (req, res, next) => {
    const username = req.body.username;
    const password = req.body.password;

    // get the user from the DB
    let user: User | null;
    try {
      user = await authDBFacade.getUser(username);

      if (!user) {
        res.status(401);
        res.json({
          status: 'ERROR',
          message: 'No user exists',
        });
        return;
      }
    } catch (err) {
      res.status(500);
      res.json({
        status: 'ERROR',
        message: 'Could not get user',
      });
      return;
    }

    // compare given and stored passwords
    try {
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
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
    } catch (err) {
      res.status(500);
      res.json({
        status: 'ERROR',
        message: 'Could not check password',
      });
      return;
    }

    next();
  };

const authenticateAccessToken: AuthHandlerFactoryFunc =
  ({ authDBFacade }) =>
  async (req, res, next) => {
    const token = req.cookies[CookieName.AccessToken];
    if (!token) {
      res.status(401);
      res.json({
        status: 'ERROR',
        message: 'Unauthorized access. No token found.',
      });
      return;
    }

    // check if token is blacklisted
    try {
      const isBlacklisted = await authDBFacade.isTokenBlacklisted(token);
      if (isBlacklisted) {
        res.status(401);
        res.json({
          status: 'ERROR',
          message: 'Unauthorized access. Supplied token cannot be used.',
        });
        return;
      }
    } catch (err) {
      res.status(500);
      res.json({
        status: 'ERROR',
        message: 'Could not verify token.',
      });
      return;
    }

    // verify token
    try {
      const payload = await verifyJWT<{ username: string }>(
        token,
        process.env['ACCESS_TOKEN_KEY'] ?? 'secret'
      );
      res.locals['user'] = {
        username: payload.username,
      };
    } catch (err) {
      res.status(401);
      res.json({
        status: 'ERROR',
        message: 'Unauthorized access. Verification of token failed.',
      });
      return;
    }

    next();
  };

const authenticateRefreshToken: AuthHandlerFactoryFunc =
  ({ authDBFacade }) =>
  async (req, res, next) => {
    const token = req.cookies[CookieName.RefreshToken];
    if (!token) {
      res.status(401);
      res.json({
        status: 'ERROR',
        message: 'Unauthorized access. No token found.',
      });
      return;
    }

    // check if token is blacklisted
    try {
      const isBlacklisted = await authDBFacade.isTokenBlacklisted(token);
      if (isBlacklisted) {
        res.status(401);
        res.json({
          status: 'ERROR',
          message: 'Unauthorized access. Supplied token cannot be used.',
        });
        return;
      }
    } catch (err) {
      res.status(500);
      res.json({
        status: 'ERROR',
        message: 'Could not verify token.',
      });
      return;
    }

    // verify token
    try {
      const payload = await verifyJWT<{ username: string }>(
        token,
        process.env['REFRESH_TOKEN_KEY'] ?? 'secret'
      );
      res.locals['user'] = {
        username: payload.username,
      };
    } catch (err) {
      res.status(401);
      res.json({
        status: 'ERROR',
        message: 'Unauthorized access. Verification of token failed.',
      });
      return;
    }

    next();
  };

const addAccessAndRefreshToken: AuthHandlerFactoryFunc =
  ({ authDBFacade }) =>
  async (req, res, next) => {
    const user = res.locals['user'];
    if (!user) {
      res.status(500);
      res.json({
        status: 'ERROR',
        message: 'Could not determine user',
      });
      return;
    }

    // if there's an access token, blacklist it
    const oldAccessToken = req.cookies[CookieName.AccessToken];
    if (oldAccessToken) {
      try {
        await authDBFacade.blacklistToken(oldAccessToken);
      } catch (err) {
        res.status(500);
        res.json({
          status: 'ERROR',
          message: 'Could not invalidate access token',
        });
        return;
      }
    }

    // if there's a refresh token, blacklist it
    const oldRefreshAccessToken = req.cookies[CookieName.RefreshToken];
    if (oldRefreshAccessToken) {
      try {
        await authDBFacade.blacklistToken(oldRefreshAccessToken);
      } catch (err) {
        res.status(500);
        res.json({
          status: 'ERROR',
          message: 'Could not invalidate refresh token',
        });
        return;
      }
    }

    // set new tokens
    let encodedAccessJWT: string;
    let encodedRefreshJWT: string;
    try {
      encodedAccessJWT = await createJWT(
        {
          username: user.username,
        },
        process.env['ACCESS_TOKEN_KEY'] ?? 'secret',
        ACCESS_TOKEN_EXPIRE_SECS
      );
      encodedRefreshJWT = await createJWT(
        {
          username: user.username,
        },
        process.env['REFRESH_TOKEN_KEY'] ?? 'secret',
        REFRESH_TOKEN_EXPIRE_SECS
      );
    } catch (err) {
      res.status(500);
      res.json({
        status: 'ERROR',
        message: 'Could not create token(s). Reason: ' + (err as Error).message,
      });
      return;
    }

    // set tokens in cookies
    const now = new Date();
    const expireAccessToken = new Date(
      now.getTime() + ACCESS_TOKEN_EXPIRE_SECS * 1000
    );
    const expireRefreshToken = new Date(
      now.getTime() + REFRESH_TOKEN_EXPIRE_SECS * 1000
    );
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
  };

interface AuthHandlers {
  validateUsernamePasswordForm: RequestHandler;
  registerUser: RequestHandler;
  authenticateUser: RequestHandler;
  authenticateAccessToken: RequestHandler;
  authenticateRefreshToken: RequestHandler;
  addAccessAndRefreshToken: RequestHandler;
}

export function createAuthHandlers(deps: AuthHandlerDeps): AuthHandlers {
  return {
    validateUsernamePasswordForm,
    registerUser: registerUser(deps),
    authenticateUser: authenticateUser(deps),
    authenticateAccessToken: authenticateAccessToken(deps),
    authenticateRefreshToken: authenticateRefreshToken(deps),
    addAccessAndRefreshToken: addAccessAndRefreshToken(deps),
  };
}

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
