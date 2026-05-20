# PetNest Server

Express and MongoDB backend for the PetNest adoption platform.

## Features
- HTTPOnly cookie JWT authentication.
- User registration, login, logout, and current-user session check.
- Pet CRUD APIs with owner-only update and delete protection.
- Adoption request APIs with requester and owner authorization.
- Search and filter support using MongoDB `$regex` and `$in` operators.
- CORS configured for credentialed client requests.

## NPM Packages Used
- express
- mongodb
- cors
- dotenv
- nodemon

## Environment Variables
Create `.env` from `.env.example`:

```bash
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
CLIENT_URL=http://localhost:3000
PORT=8080
```

## Run Locally

```bash
npm install
npm run dev
```
