import express, { RequestHandler } from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import { config } from 'dotenv';

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

const validateRegistrationForm: RequestHandler = (req, res, next) => {
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
const FAKE_DB: Record<string, any> = {};

const registerUser: RequestHandler = (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;

  if (FAKE_DB[username]) {
    res.status(409);
    res.json({
      status: 'ERROR',
      message: 'User already exists',
    });
    return;
  }

  // TODO: hash password

  FAKE_DB[username] = {
    username,
    password,
  };

  next();
};

const addAccessAndRefreshToken: RequestHandler = (_, res, next) => {
  const now = new Date();
  const expireAccessToken = new Date(now.getTime() + 15 * 60 * 1000);
  const expireRefreshToken = new Date(now.getTime() + 120 * 60 * 1000);

  // TODO: use real access and refresh token
  res.cookie('accessToken', 'asdfasdfasdf', {
    expires: expireAccessToken,
    httpOnly: true,
    sameSite: 'lax',
  });
  res.cookie('refreshToken', 'asdfasdfasdf', {
    expires: expireRefreshToken,
    httpOnly: true,
    sameSite: 'lax',
  });

  next();
};

app.post(
  '/register',
  validateRegistrationForm,
  registerUser,
  addAccessAndRefreshToken,
  (_, res) => {
    res.json({
      status: 'SUCCESS',
      message: 'Registered user',
    });
  }
);

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
