---
title: "Deta + FastAPI + JWT Auth Part 1"
date: 2021-04-12
draft: false
---


# Deta + FastAPI + JWT Auth Part 1

This is the first of a two part series on implementing authorization in a FastAPI application using Deta. In this article, we will learn about JWT tokens, set up the project, and build the auth logic. In the next article, we will implement the auth logic in a FastAPI application. [The full code is available here.](https://github.com/rohanshiva/Deta-FastAPI-JWT-Auth-Blog) 

## Introduction

Implementing authorization can be useful, as it provides the client access to a specific set of functions, actions, data, etc. Consider an e-commerce website, you would want to make sure users are authorized before they can look at items in the cart. Another example is a chat application where only the owner has the right to add/remove people. 

JWT (or JSON web tokens) are simply encrypted strings that encode some information about the client. These tokens are signed using a secret key or a public/private key. We will implement the former method. Essentially, when the client is logged in, the server sends back a response with a signed token. Subsequently, the client can send requests to the server with the token as a header to access authorized routes, data, functions etc. 

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
```

In the next article, we will implement the logic in a FastAPI application and deploy our app on Deta micros! [The full code is available here.](https://github.com/rohanshiva/Deta-FastAPI-JWT-Auth-Blog)
