import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import { config } from 'dotenv';
import { createAuthHandlers } from './auth';
import { createInMemoryAuthDB } from './authDB';
import { onlyApplicationJson } from './middleware';

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

app.use(onlyApplicationJson);

const inMemoryAuthDB = createInMemoryAuthDB();

const {
  validateUsernamePasswordForm,
  registerUser,
  authenticateUser,
  authenticateAccessToken,
  authenticateRefreshToken,
  addAccessAndRefreshToken,
} = createAuthHandlers({
  authDBFacade: inMemoryAuthDB,
});

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
