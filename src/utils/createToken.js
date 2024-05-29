import jwt from "jsonwebtoken";

const maxAge = 3 * 24 * 60 * 60;
export const createToken = (params, secret, expiresIn = null) => {
  return jwt.sign({ ...params }, secret, {
    expiresIn: expiresIn ?? maxAge,
  });
};
