const express = require('express')
const dotenv = require('dotenv')
const cors = require('cors')
const { MongoClient, ObjectId, ServerApiVersion } = require('mongodb');
const crypto = require('crypto')


dotenv.config()

const app = express()
const port = process.env.PORT || 8080
const uri = process.env.MONGODB_URI
const jwtSecret = process.env.JWT_SECRET || 'petnest-local-secret'
const clientUrl = process.env.CLIENT_URL || 'http://localhost:3000'
const isProduction = process.env.NODE_ENV === 'production'


app.use(express.json())
app.use(cors({
  origin: [clientUrl, 'http://localhost:3000'],
  credentials: true,
}))

if (!uri) {
  throw new Error('MONGODB_URI is missing from .env')
}

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverSelectionTimeoutMS: 5000,
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

const cookieOptions = {
  httpOnly: true,
  secure: isProduction,
  sameSite: isProduction ? 'none' : 'lax',
  maxAge: 7 * 24 * 60 * 60 * 1000,
  path: '/',
}

function base64url(input) {
  return Buffer.from(input).toString('base64url')
}

function signToken(payload) {
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const body = base64url(JSON.stringify({ ...payload, exp: Date.now() + cookieOptions.maxAge }))
  const signature = crypto
    .createHmac('sha256', jwtSecret)
    .update(`${header}.${body}`)
    .digest('base64url')

  return `${header}.${body}.${signature}`
}

function verifyJwt(token) {
  if (!token) return null

  try {
    const [header, body, signature] = token.split('.')
    if (!header || !body || !signature) return null

    const expected = crypto.createHmac('sha256', jwtSecret).update(`${header}.${body}`).digest('base64url')
    if (Buffer.byteLength(signature) !== Buffer.byteLength(expected)) return null
    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null

    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'))
    if (payload.exp && payload.exp < Date.now()) return null

    return payload
  } catch {
    return null
  }
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex')
  return `${salt}:${hash}`
}

function checkPassword(password, savedHash = '') {
  const [salt] = savedHash.split(':')
  if (!salt) return false
  return hashPassword(password, salt) === savedHash
}

function parseCookies(cookieHeader = '') {
  return cookieHeader.split(';').reduce((cookies, item) => {
    const [key, ...rest] = item.trim().split('=')
    if (key) cookies[key] = decodeURIComponent(rest.join('='))
    return cookies
  }, {})
}

function requireAuth(req, res, next) {
  const cookies = parseCookies(req.headers.cookie)
  const user = verifyJwt(cookies.petnest_token)

  if (!user?.email) {
    return res.status(401).send({ message: 'Unauthorized access' })
  }

  req.user = user
  next()
}

function cleanUser(user) {
  if (!user) return null

  return {
    _id: user._id,
    name: user.name,
    email: user.email,
    photoURL: user.photoURL || '',
    createdAt: user.createdAt,
  }
}


app.get('/', (req, res) => {
  res.send('Petnest server is running')
})

async function run() {
  try {
    await client.connect();
    const db = client.db('petnest')
    const petsCollection = db.collection('pets')
    const usersCollection = db.collection('users')
await usersCollection.createIndex({ email: 1 }, { unique: true })
   
    app.post('/auth/register', async (req, res) => {
  try {
    const { name, email, photoURL, password } = req.body

    if (!name || !email || !password) {
      return res.status(400).send({ message: 'Name, email and password are required' })
    }

    const passwordHash = hashPassword(password)
    const user = {
      name,
      email: email.toLowerCase(),
      photoURL,
      passwordHash,
      createdAt: new Date(),
    }

    await usersCollection.insertOne(user)
    res.status(201).send({ message: 'Registration successful' })
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).send({ message: 'This email is already registered' })
    }

    res.status(500).send({ message: 'Registration failed' })
  }
})

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body
  const user = await usersCollection.findOne({ email: email?.toLowerCase() })

  if (!user || !checkPassword(password, user.passwordHash)) {
    return res.status(401).send({ message: 'Invalid email or password' })
  }

  res.cookie('petnest_token', signToken({ email: user.email, name: user.name }), cookieOptions)
  res.send({ user: cleanUser(user) })
})

app.post('/auth/logout', (req, res) => {
  res.clearCookie('petnest_token', { ...cookieOptions, maxAge: 0 })
  res.send({ message: 'Logged out' })
})

app.post('/auth/google', async (req, res) => {
  const { name, email, photoURL } = req.body

  if (!email) {
    return res.status(400).send({ message: 'Email is required' })
  }

  await usersCollection.updateOne(
    { email: email.toLowerCase() },
    {
      $setOnInsert: { createdAt: new Date() },
      $set: {
        name,
        email: email.toLowerCase(),
        photoURL,
      },
    },
    { upsert: true }
  )

  const user = await usersCollection.findOne({ email: email.toLowerCase() })
  res.cookie('petnest_token', signToken({ email: user.email, name: user.name }), cookieOptions)
  res.send({ user: cleanUser(user) })
})

app.get('/auth/me', requireAuth, async (req, res) => {
  const user = await usersCollection.findOne({ email: req.user.email })
  res.send({ user: cleanUser(user) })
})

function normalizePet(body, ownerEmail) {
  const petName = body.petName || body.name
  const imageUrl = body.imageUrl || body.image

  return {
    petName,
    name: petName,
    species: body.species,
    breed: body.breed,
    age: Number(body.age) || 0,
    gender: body.gender,
    imageUrl,
    image: imageUrl,
    healthStatus: body.healthStatus,
    vaccinationStatus: body.vaccinationStatus,
    location: body.location,
    adoptionFee: Number(body.adoptionFee) || 0,
    description: body.description,
    ownerEmail,
  }
}

function getPetName(pet) {
  return pet?.petName || pet?.name || 'Pet'
}

function getPetImage(pet) {
  return pet?.imageUrl || pet?.image || ''
}

    app.get('/pets', async (req, res) => {
      try {
        const results = await petsCollection.find().toArray()
        res.send(results)
      } catch (error) {
        console.error('Failed to fetch pets:', error.message)
        res.status(500).send({ message: 'Failed to fetch pets' })
      }
    });

    app.get('/pets/:_id', async (req, res) => {
      try {
        const { _id } = req.params

        if (!ObjectId.isValid(_id)) {
          return res.status(400).send({ message: 'Invalid pet id' })
        }

        const query = { _id: new ObjectId(_id) }
        const result = await petsCollection.findOne(query)

        if (!result) {
          return res.status(404).send({ message: 'Pet not found' })
        }

        res.send(result)
      } catch (error) {
        console.error('Failed to fetch pet:', error.message)
        res.status(500).send({ message: 'Failed to fetch pet' })
      }
    
    })
     


    await client.db("admin").command({ ping: 1 });
    console.log("Successfully connected to MongoDB!");

    const database = client.db('petnest')
    app.locals.db = database

    app.listen(port, () => {
      console.log(`Petnest server listening on port ${port}`)
    })
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error)
    process.exit(1)
  }
}

run()

