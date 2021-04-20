---
title: "Get started with FastAPI JWT authentication – Part 1"
date: 2021-04-13
draft: false
---

# Get started with FastAPI JWT authentication – Part 1

This is the first of a two part series on implementing authorization in a FastAPI application using Deta. In this article, we will learn about JWT tokens, set up the project, and build the auth logic. In the next article, we will implement the auth logic in a FastAPI application. [The full code is available here.](https://github.com/rohanshiva/Deta-FastAPI-JWT-Auth-Blog) 

## Introduction

Implementing authorization can be useful, as it provides the client access to a specific set of functions, actions, data, etc. Consider an e-commerce website, you would want to make sure users are authorized before they can look at items in the cart. Another example is a chat application where only the owner has the right to add/remove people. 

JWT (or JSON web tokens) are simply base64 strings that encode some information about the client. These tokens are signed using a secret key or a public/private key. We will implement the former method. Essentially, when the client is logged in, the server sends back a response with a signed token. Subsequently, the client can send requests to the server with the token as a header to access authorized routes, data, functions etc. 

![image](https://user-images.githubusercontent.com/20916697/114433979-15e32f80-9b88-11eb-8bd9-a4bfb5f3b56c.png)

**Let's get started**

## Agenda

- Setup
- FastAPI app skeleton + Auth logic

## Setup

### Tools

- [FastAPI](https://fastapi.tiangolo.com/): we are using FastAPI to build the application
- Deta Base (Base) : database for our application
- Deta Micro: host our application
- `pyjwt`: library for encoding and decoding JWT tokens
- `passlib[bcrypt]`: password hashing library

### Install

To get started, create a folder for this project `fastapi-jwt` , and create a `requirements.txt` file with the following lines:

```python
deta
fastapi
uvicorn
pyjwt
passlib[bcrypt]
```

Run the following command to install the libraries 

`pip install -r requirements.txt`

Before we begin with the project we also need to get a Deta project key to use with Deta Base. We are using Base to store user account information such as username and hashed password.  

To do that, navigate to the [Deta Console ](https://web.deta.sh/)then click on the arrow on the top left.
If you don't already have a Deta account, [create one for free](https://web.deta.sh/). Once you confirm your email, Deta will automatically generate a Project Key, this is the one we need, copy it and  store it securely.


![image](https://user-images.githubusercontent.com/20916697/114434048-2dbab380-9b88-11eb-8839-22bebae709ed.png)

Create a new project and make sure to save the key in a secure place!

![image](https://user-images.githubusercontent.com/20916697/114434122-40cd8380-9b88-11eb-8ddc-7045ce5756ba.png)

Add the key to your environment variables like this `DETA_PROJECT_KEY=YOUR_COPIED_PROJECT_KEY`

That's it for the setup, we have everything we need to get rolling. Let's go!

## FastAPI app skeleton and Auth logic

Here is how our folder structure will look like at the end:

```json

fastapi-jwt/
    ├── main.py
    ├── auth.py
    ├── user_modal.py
    └── requirements.txt
```

In `main.py` , let's set up our FastAPI application, Deta Base, and skeletons for all the endpoints.  

```python
from fastapi import FastAPI, HTTPException
from deta import Deta

deta = Deta()
users_db = deta.Base('users')

app = FastAPI()

@app.post('/signup')
def signup():
    return 'Sign up endpoint'

@app.post('/login')
def login():
    return 'Login user endpoint'

@app.get('/refresh_token')
def refresh_token():
    return 'New token'

@app.post('/secret')
def secret_data():
    return 'Secret data'

@app.get('/notsecret')
def not_secret_data():
    return 'Not secret data'
```

`users_db` is our base where we store the account's hashed password. The schema for `users` will look like the following:

```python
{
	key: str, # username
	encoded_password: str
}
```

Now let's head over to `auth.py`, to handle the authentication logic:

```python
import os
import jwt # used for encoding and decoding jwt tokens
from fastapi import HTTPException # used to handle error handling
from passlib.context import CryptContext # used for hashing the password 
from datetime import datetime, timedelta # used to handle expiry time for tokens

class Auth():
    hasher= CryptContext(schemes=['bcrypt'])
    secret = os.getenv("APP_SECRET_STRING")

    def encode_password(self, password):
        return self.hasher.hash(password)

    def verify_password(self, password, encoded_password):
        return self.hasher.verify(password, encoded_password)
```

So far, we just imported all the tools from the libraries, and we created the `Auth` class with two functions. We don't want to store the plain text password in our `users` Base. Therefore, we can use the `encode_password` function to encode the password using the `passlib['bcrypt']` library. We can store this encoded password in our `users_db` base when the user makes an account. 

We also have another function `verify_password` which checks if the plain password and the encoded password from `users_db` match. This can be useful to verify user in the `/login` endpoint. 

Notice that we get the variable `secret` from our environment, make sure to generate a long secure string and store it in your environment variables under the name `APP_SECRET_STRING`.

Now that we have a way to verify passwords, and hash passwords, it is time to handle the logic for encoding and decoding JSON web tokens. The tokens are the essence of auth logic. 

Inside the `Auth` class, add the following functions.  

```python
def encode_token(self, username):
        payload = {
            'exp' : datetime.utcnow() + timedelta(days=0, minutes=30),
            'iat' : datetime.utcnow(),
            'sub' : username
        }
        return jwt.encode(
            payload, 
            self.secret,
            algorithm='HS256'
        )
    
def decode_token(self, token):
        try:
            payload = jwt.decode(token, self.secret, algorithms=['HS256'])
            return payload['sub']
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Token expired')
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail='Invalid token')
```

The `encode_token` function takes a username as a parameter and uses `pyjwt` to encode the token. We are using `timedelta` to set the expiry of the token for 30 mins. We can use this function inside the `/login` endpoint, and return a token to the client. 

`decode_token` takes a token as a parameter, and attempts to decode it using the `secret`. If there are any errors like expired token or an invalid token, we can simply raise an `HTTPException`. Otherwise, we can return the username. This will be helpful to us when the client interacts with protected data, functions, etc. We can use this function to simply verify if they have access to the response. 

We need one more function to refresh a token when expired. 
```python
    def refresh_token(self, expired_token):
        try:
            payload = jwt.decode(expired_token, self.secret, algorithms=['HS256'], options= {'verify_exp': False})
	    username = payload['sub']
	    new_token = self.encode_token(username)
            return {'token': new_token}
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail='Invalid token')
```
Here we are using the same decode function from `pyjwt`, however, by including the option `{'verify_exp': False}` we can ignore the `ExpiredSignatureError` and get the username from the expired token. We can then use this to create a new one.

That is all we need for the auth logic! Here is what the file looks like at the end:

`auth.py`

```python
import os
import jwt # used for encoding and decoding jwt tokens
from fastapi import HTTPException # used to handle error handling
from passlib.context import CryptContext # used for hashing the password 
from datetime import datetime, timedelta # used to handle expiry time for tokens

class Auth():
    hasher= CryptContext(schemes=['bcrypt'])
    secret = os.getenv("APP_SECRET_STRING")

    def encode_password(self, password):
        return self.hasher.hash(password)

    def verify_password(self, password, encoded_password):
        return self.hasher.verify(password, encoded_password)
    
    def encode_token(self, username):
        payload = {
            'exp' : datetime.utcnow() + timedelta(days=0, minutes=30),
            'iat' : datetime.utcnow(),
            'sub' : username
        }
        return jwt.encode(
            payload, 
            self.secret,
            algorithm='HS256'
        )
    
    def decode_token(self, token):
        try:
            payload = jwt.decode(token, self.secret, algorithms=['HS256'])
            return payload['sub']
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Token expired')
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail='Invalid token')
	    
    def refresh_token(self, expired_token):
        try:
            payload = jwt.decode(expired_token, self.secret, algorithms=['HS256'], options= {'verify_exp': False})
	    username = payload['sub']
	    new_token = self.encode_token(username)
            return {'token': new_token}
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail='Invalid token')
```

In the next article, we will implement the logic in a FastAPI application and deploy our app on Deta micros! [The full code is available here.](https://github.com/rohanshiva/Deta-FastAPI-JWT-Auth-Blog)


---
title: "Get started with FastAPI JWT authentication – Part 2"
date: 2021-04-13
draft: false
---
# Get started with FastAPI JWT authentication – Part 2
This is the second of a two part series on implementing authorization in a FastAPI application using Deta. In the previous article, we learned a bit about JWT, set up the project, and finished the building blocks of authorization logic. In this article, let's implement the logic, and deploy our app on Deta micros! [The full code is available here.](https://github.com/rohanshiva/Deta-FastAPI-JWT-Auth-Blog) 

## Implementing the auth logic

Before we implement the auth logic, let's create a data modal for login and signup details. 

In `user_modal.py` :

```python
from pydantic import BaseModel

class AuthModal(BaseModel):
    username: str
    password: str
```

This modal represents the data that we can expect from the client when they hit `/login` or `/signup` endpoints.

Update the `main.py` , with the following import statements

```python
from auth import Auth
from user_modal import AuthModal
from fastapi import FastAPI, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
```

Also, we will create an `auth_handler` to access the logic from the `Auth` class. We will use `security` in our protected endpoints to access the token from the request header.

```python
security = HTTPBearer()
auth_handler = Auth()
```

Here is the code for `/signup` endpoint. 

```python
@app.post('/signup')
def signup(user_details: AuthModal):
    if users_db.get(user_details.username) != None:
        return 'Account already exists'
    try:
        hashed_password = auth_handler.encode_password(user_details.password)
        user = {'key': user_details.username, 'password': hashed_password}
        return users_db.put(user)
    except:
        error_msg = 'Failed to signup user'
        return error_msg
```

In this function we are checking if a user with the username already exists in our `users_db`. If so, we can simply return a message indicating that the account already exists. If the user doesn't already exists we can hash the password using the `encode_password` function from `auth.py` and store the user in `users_db`. In case of any errors while adding the user to the base, we can return a failure message. 

`/login` endpoint is pretty simple. This also takes in the argument `user_details` , which has the username and password. 

```python
@app.post('/login')
def login(user_details: AuthModal):
    user = users_db.get(user_details.username)
    if (user is None):
        return HTTPException(status_code=401, detail='Invalid username')
    if (not auth_handler.verify_password(user_details.password, user['password'])):
        return HTTPException(status_code=401, detail='Invalid password')
    
    token = auth_handler.encode_token(user['key'])
    return {'token': token}
```

If the account with the username doesn't exist, or if the hashed password in the `users_db` doesn't match the input password we can simply raise an `HTTPException`. Otherwise, we can return the encoded JWT token using `encode_token`.

```python
@app.post('/secret')
def secret_data(credentials: HTTPAuthorizationCredentials = Security(security)):
    token = credentials.credentials
    if(auth_handler.decode_token(token)):
        return 'Top Secret data only authorized users can access this info'

@app.get('/notsecret')
def not_secret_data():
    return 'Not secret data'
```

The `/secret` endpoint only returns the "Secret Data" if the token argument is valid. However, if the token is invalid or an expired token, then `decode_token` raises a `HTTPException`. The token is usually passed in the request header as `Authorization: Bearer <token>`. Therefore, to get the token we can wrap the input `credentials` around `HTTPAuthorizationCredentials` tag. Now we can access the token from the request header in `credentials.credentials`. 

The `/not_secret` endpoint is an example of an unprotected endpoint, which doesn't require any authentication.

```python
@app.get('/refresh_token')
def refresh_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    expired_token = credentials.credentials
    return auth_handler.refresh_token(expired_token)
```

`/refresh_token` endpoint is also pretty simple, it receives an expired token which is then passed onto the the `refresh_token` function from auth logic to get the new token. 

Here is a look at `main.py` at the end:

```python
from fastapi import FastAPI, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from auth import Auth
from user_modal import AuthModal

deta = Deta()
users_db = deta.Base('users')

app = FastAPI()

security = HTTPBearer()
auth_handler = Auth()

@app.post('/signup')
def signup(user_details: AuthModal):
    if users_db.get(user_details.username) != None:
        return 'Account already exists'
    try:
        hashed_password = auth_handler.encode_password(user_details.password)
        user = {'key': user_details.username, 'password': hashed_password}
        return users_db.put(user)
    except:
        error_msg = 'Failed to signup user'
        return error_msg

@app.post('/login')
def login(user_details: AuthModal):
    user = users_db.get(user_details.username)
    if (user is None):
        return HTTPException(status_code=401, detail='Invalid username')
    if (not auth_handler.verify_password(user_details.password, user['password'])):
        return HTTPException(status_code=401, detail='Invalid password')
    
    token = auth_handler.encode_token(user['key'])
    return {'token': token}

@app.get('/refresh_token')
def refresh_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    expired_token = credentials.credentials
    return auth_handler.refresh_token(expired_token)

@app.post('/secret')
def secret_data(credentials: HTTPAuthorizationCredentials = Security(security)):
    token = credentials.credentials
    if(auth_handler.decode_token(token)):
        return 'Top Secret data only authorized users can access this info'

@app.get('/notsecret')
def not_secret_data():
    return 'Not secret data'
```

To test the app, go to the terminal in the same directory and run `uvicorn main:app`, you can then go `/docs` on the local endpoint (for me it was [`http://127.0.0.1:8000/docs`](http://127.0.0.1:8000/docs)) to test the application.

`/signup`

```json
curl -X 'POST' \
  'http://127.0.0.1:8000/signup' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "username": "flyingsponge",
  "password": "SpongePassword"
}'

Response Body
{
  "key": "flyingsponge",
  "password": "$2b$12$/Gq7g40zZ4/sQ9iWfqVze.Jx5HI5XwCrERITGG/wZivuZ9jhkd0bK"
}
```

`/login`

```json
curl -X 'POST' \
  'http://127.0.0.1:8000/login' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "username": "flyingsponge",
  "password": "SpongePassword"
}'

Response Body
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTgyNDE1MjAsImlhdCI6MTYxODIzOTcyMCwic3ViIjoiZmx5aW5nc3BvbmdlIn0.SoMeSo_b9z4fC-XnR8bepUbFvWvSEw9rRQ9LMJNzm3k"
}
```

`/secret`

```python
curl -X 'POST' \
  'http://127.0.0.1:8000/secret' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTg5MzU3MzcsImlhdCI6MTYxODkzNTY3Nywic3ViIjoicm9oYW4ifQ.dja0E6SUaZfEvYVKySjLE9OLXOtob5pjpy3R_rlCD7c' \
  -d ''

Response body
"Top Secret data only authorized users can access this info"
```

`/notsecret`

```json
curl -X 'GET' \
  'http://127.0.0.1:8000/notsecret' \
  -H 'accept: application/json'

Response Body
"Not secret data"
```

`/secret`

```json
curl -X 'POST' \
  'http://127.0.0.1:8000/secret' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTg5MzU3MzcsImlhdCI6MTYxODkzNTY3Nywic3ViIjoicm9oYW4ifQ.dja0E6SUaZfEvYVKySjLE9OLXOtob5pjpy3R_rlCD7c' \
  -d ''
Response Body
{
  "detail": "Token expired"
}
```

Now that the token is expired, let's get a new one

`/refresh_token`

```json
curl -X 'GET' \
  'http://127.0.0.1:8000/refresh_token' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTg5MzU3MzcsImlhdCI6MTYxODkzNTY3Nywic3ViIjoicm9oYW4ifQ.dja0E6SUaZfEvYVKySjLE9OLXOtob5pjpy3R_rlCD7c'

Response Body
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTg5MzU5MDcsImlhdCI6MTYxODkzNTg0Nywic3ViIjoicm9oYW4ifQ.VI1vqMZ2Mklue-bv5WtwhFxbVsbHkRHOr3fON49wpmE"
}
```

## Deploy on Deta micros
Before we begin, make sure to [install the Deta CLI.](https://docs.deta.sh/docs/cli/install) After installing, run the following commands in the same directory to deploy our app on Deta micros.

```json
deta login
```
We also need to add a `.env` file with the secret.

```
APP_SECRET_STRING=SECRET_STRING
```

Now we need to update our micro by doing:

```python
deta new 
deta update -e .env
deta deploy
```



## Summary

Our simple FastAPI application with JWT auth is now ready! As you can probably tell, we are not doing anything "secret" with our authorization. This article is just a template for implementing authorization. You can build on this template to build a fullstack application that relies on authorization. [The full code is available here.](https://github.com/rohanshiva/Deta-FastAPI-JWT-Auth-Blog)
