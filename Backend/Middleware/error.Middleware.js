import ApiError from '../Utils/apiError.js';

export const notFound = (req, res, next) =>
  next(new ApiError(404, `Route not found: ${req.originalUrl}`));

// eslint-disable-next-line no-unused-vars
export const errorHandler = (err, req, res, next) => {
  const statusCode = err.statusCode || 500;

  res.status(statusCode).json({
    success: false,
    message: err.message,
    ...(err.details ? { details: err.details } : {}),
    ...(process.env.NODE_ENV === 'development' ? { stack: err.stack } : {}),
  });
};
