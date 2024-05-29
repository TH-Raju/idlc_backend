const sendResponse = (res, statusCode, success, message, data) => {
  res.status(statusCode).json({
    statusCode: statusCode,
    success: success,
    message: message || null || undefined,
    data: data || null || undefined,
  });
};

export default sendResponse;
