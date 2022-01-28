import { RequestHandler } from "express";

export const onlyApplicationJson: RequestHandler = (req, res, next) => {
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