# How to Start server- Follow this steps:

- Download Code
- open in vs code
- setup .env like demo.env file
- run this command (one time in a project)
  ```
  npm install
  ```
- open and Start mongodb compass
- open and Start Postman
- Run on Terminal to start server

  ```
  npm run dev
  ```

- Run the below api on postman with this like data

## Auth

- http://localhost:8000/api/v1/users/signup (POST - create account)

  ```
  {
    "fullName": "Temp user",
    "phone": "0189456485",
    "email": "idlc@gmail.com",
    "password": "hello123",
    "role": "admin"
    }
  ```

- http://localhost:8000/api/v1/users/verify-otp (POST - verify account)

  ```
  {
    "otp": 742093,
    "userToken": "Token"
  }
  ```

- http://localhost:8000/api/v1/users/login (POST - Login account)
  ```
  {
    "email": "idlc@gmail.com",
    "password": "hello123"
  }
  ```
