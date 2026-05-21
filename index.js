const crypto = require('crypto');
const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const { MongoClient, ObjectId, ServerApiVersion } = require('mongodb');

dotenv.config();

const app = express();
const port = process.env.PORT || 8080;
const uri = process.env.MONGODB_URI;
const jwtSecret = process.env.JWT_SECRET || 'petnest-local-secret';
const clientUrl = process.env.CLIENT_URL || 'http://localhost:3000';
const isProduction = process.env.NODE_ENV === 'production';

app.use(
  cors({
    origin: [clientUrl, 'http://localhost:3000'],
    credentials: true,
  })
);
app.use(express.json());

if (!uri) {
  throw new Error('MONGODB_URI is missing from .env');
}

const client = new MongoClient(uri, {
  serverSelectionTimeoutMS: 5000,
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const cookieOptions = {
  httpOnly: true,
  secure: isProduction,
  sameSite: isProduction ? 'none' : 'lax',
  maxAge: 7 * 24 * 60 * 60 * 1000,
  path: '/',
};

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

function signToken(payload) {
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64url(JSON.stringify({ ...payload, exp: Date.now() + cookieOptions.maxAge }));
  const signature = crypto
    .createHmac('sha256', jwtSecret)
    .update(`${header}.${body}`)
    .digest('base64url');

  return `${header}.${body}.${signature}`;
}

function verifyJwt(token) {
  if (!token) return null;

  try {
    const [header, body, signature] = token.split('.');
    if (!header || !body || !signature) return null;

    const expected = crypto.createHmac('sha256', jwtSecret).update(`${header}.${body}`).digest('base64url');
    if (Buffer.byteLength(signature) !== Buffer.byteLength(expected)) return null;
    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;

    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (payload.exp && payload.exp < Date.now()) return null;

    return payload;
  } catch {
    return null;
  }
}

function parseCookies(cookieHeader = '') {
  return cookieHeader.split(';').reduce((cookies, item) => {
    const [key, ...rest] = item.trim().split('=');
    if (key) cookies[key] = decodeURIComponent(rest.join('='));
    return cookies;
  }, {});
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

function checkPassword(password, savedHash = '') {
  const [salt] = savedHash.split(':');
  if (!salt) return false;
  return hashPassword(password, salt) === savedHash;
}

function requireAuth(req, res, next) {
  const cookies = parseCookies(req.headers.cookie);
  const user = verifyJwt(cookies.petnest_token);

  if (!user?.email) {
    return res.status(401).send({ message: 'Unauthorized access' });
  }

  req.user = user;
  next();
}

function cleanUser(user) {
  if (!user) return null;
  return {
    _id: user._id,
    name: user.name,
    email: user.email,
    photoURL: user.photoURL || '',
    createdAt: user.createdAt,
  };
}

function normalizePet(body, ownerEmail) {
  const petName = body.petName || body.name;
  const imageUrl = body.imageUrl || body.image;

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
  };
}

function getPetName(pet) {
  return pet?.petName || pet?.name || 'Pet';
}

function getPetImage(pet) {
  return pet?.imageUrl || pet?.image || '';
}

app.get('/', (req, res) => {
  res.send('PetNest server is running');
});

async function run() {
  try {
    await client.connect();
    const db = client.db('petnest');
    const usersCollection = db.collection('users');
    const petsCollection = db.collection('pets');
    const requestsCollection = db.collection('requests');

    await usersCollection.createIndex({ email: 1 }, { unique: true });
    await petsCollection.createIndex({ petName: 1, name: 1, species: 1, ownerEmail: 1, status: 1 });
    await requestsCollection.createIndex({ petId: 1, userEmail: 1 }, { unique: true });

    app.post('/auth/register', async (req, res) => {
      try {
        const { name, email, photoURL, password } = req.body;
        if (!name || !email || !password) {
          return res.status(400).send({ message: 'Name, email and password are required' });
        }

        const passwordHash = hashPassword(password);
        const user = { name, email: email.toLowerCase(), photoURL, passwordHash, createdAt: new Date() };
        await usersCollection.insertOne(user);
        res.status(201).send({ message: 'Registration successful' });
      } catch (error) {
        if (error.code === 11000) {
          return res.status(409).send({ message: 'This email is already registered' });
        }
        res.status(500).send({ message: 'Registration failed' });
      }
    });

    app.post('/auth/login', async (req, res) => {
      const { email, password } = req.body;
      const user = await usersCollection.findOne({ email: email?.toLowerCase() });

      if (!user || !checkPassword(password, user.passwordHash)) {
        return res.status(401).send({ message: 'Invalid email or password' });
      }

      res.cookie('petnest_token', signToken({ email: user.email, name: user.name }), cookieOptions);
      res.send({ user: cleanUser(user) });
    });

    app.post('/auth/google', async (req, res) => {
      const { name, email, photoURL } = req.body;
      if (!email) return res.status(400).send({ message: 'Email is required' });

      await usersCollection.updateOne(
        { email: email.toLowerCase() },
        { $setOnInsert: { createdAt: new Date() }, $set: { name, email: email.toLowerCase(), photoURL } },
        { upsert: true }
      );

      const user = await usersCollection.findOne({ email: email.toLowerCase() });
      res.cookie('petnest_token', signToken({ email: user.email, name: user.name }), cookieOptions);
      res.send({ user: cleanUser(user) });
    });

    app.post('/auth/logout', (req, res) => {
      res.clearCookie('petnest_token', { ...cookieOptions, maxAge: 0 });
      res.send({ message: 'Logged out' });
    });

    app.get('/auth/me', requireAuth, async (req, res) => {
      const user = await usersCollection.findOne({ email: req.user.email });
      res.send({ user: cleanUser(user) });
    });

    app.post('/auth/change-password', requireAuth, async (req, res) => {
      const { currentPassword, newPassword } = req.body;
      if (!currentPassword || !newPassword) {
        return res.status(400).send({ message: 'Current password and new password are required' });
      }

      if (newPassword.length < 6) {
        return res.status(400).send({ message: 'New password must be at least 6 characters' });
      }

      const user = await usersCollection.findOne({ email: req.user.email });
      if (!user || !checkPassword(currentPassword, user.passwordHash)) {
        return res.status(401).send({ message: 'Current password is incorrect' });
      }

      const passwordHash = hashPassword(newPassword);
      await usersCollection.updateOne({ email: req.user.email }, { $set: { passwordHash } });
      res.send({ message: 'Password updated successfully' });
    });

    app.get('/pets', async (req, res) => {
      const { petName = '', search = '', species = '', status = '', featured = '', sort = 'newest' } = req.query;
      const conditions = [];

      const nameSearch = petName || search;
      if (nameSearch) {
        const searchPattern = { $regex: nameSearch, $options: 'i' };
        conditions.push({ $or: [{ petName: searchPattern }, { name: searchPattern }] });
      }
      if (species) conditions.push({ species: { $in: species.split(',').filter(Boolean) } });
      if (status === 'available') {
        conditions.push({ $or: [{ status: 'available' }, { status: { $exists: false } }] });
      } else if (status) {
        conditions.push({ status });
      }

      const query = conditions.length ? { $and: conditions } : {};

      const sortMap = {
        feeLow: { adoptionFee: 1 },
        feeHigh: { adoptionFee: -1 },
        ageLow: { age: 1 },
        newest: { createdAt: -1 },
      };

      const cursor = petsCollection.find(query).sort(sortMap[sort] || sortMap.newest);
      if (featured === 'true') cursor.limit(6);

      res.send(await cursor.toArray());
    });

    app.post('/pets', requireAuth, async (req, res) => {
      const pet = {
        ...normalizePet(req.body, req.user.email),
        status: 'available',
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await petsCollection.insertOne(pet);
      res.status(201).send({ insertedId: result.insertedId, message: 'Pet added successfully' });
    });

    app.get('/pets/:id', async (req, res) => {
      if (!ObjectId.isValid(req.params.id)) return res.status(400).send({ message: 'Invalid pet id' });

      const pet = await petsCollection.findOne({ _id: new ObjectId(req.params.id) });
      if (!pet) return res.status(404).send({ message: 'Pet not found' });
      res.send(pet);
    });

    app.patch('/pets/:id', requireAuth, async (req, res) => {
      if (!ObjectId.isValid(req.params.id)) return res.status(400).send({ message: 'Invalid pet id' });

      const result = await petsCollection.updateOne(
        { _id: new ObjectId(req.params.id), ownerEmail: req.user.email },
        { $set: { ...normalizePet(req.body, req.user.email), updatedAt: new Date() } }
      );

      if (!result.matchedCount) return res.status(403).send({ message: 'Only the owner can update this pet' });
      res.send({ message: 'Pet updated successfully' });
    });

    app.delete('/pets/:id', requireAuth, async (req, res) => {
      if (!ObjectId.isValid(req.params.id)) return res.status(400).send({ message: 'Invalid pet id' });

      const petId = req.params.id;
      const result = await petsCollection.deleteOne({ _id: new ObjectId(petId), ownerEmail: req.user.email });
      if (!result.deletedCount) return res.status(403).send({ message: 'Only the owner can delete this pet' });

      await requestsCollection.deleteMany({ petId });
      res.send({ message: 'Pet deleted successfully' });
    });

    app.get('/owners/pets', requireAuth, async (req, res) => {
      const pets = await petsCollection.find({ ownerEmail: req.user.email }).sort({ createdAt: -1 }).toArray();
      res.send(pets);
    });

    app.post('/requests', requireAuth, async (req, res) => {
      const { petId, pickupDate, message } = req.body;
      if (!ObjectId.isValid(petId)) return res.status(400).send({ message: 'Invalid pet id' });

      const pet = await petsCollection.findOne({ _id: new ObjectId(petId) });
      if (!pet) return res.status(404).send({ message: 'Pet not found' });
      if (pet.ownerEmail === req.user.email) return res.status(403).send({ message: 'Owners cannot request their own pets' });
      if (pet.status === 'adopted') return res.status(409).send({ message: 'This pet is already adopted' });

      const request = {
        petId,
        petName: getPetName(pet),
        petImage: getPetImage(pet),
        ownerEmail: pet.ownerEmail,
        userName: req.user.name,
        userEmail: req.user.email,
        pickupDate,
        message,
        status: 'pending',
        createdAt: new Date(),
      };

      try {
        const result = await requestsCollection.insertOne(request);
        res.status(201).send({ insertedId: result.insertedId, message: 'Adoption request submitted' });
      } catch (error) {
        if (error.code === 11000) return res.status(409).send({ message: 'You already requested this pet' });
        res.status(500).send({ message: 'Request failed' });
      }
    });

    app.get('/requests/mine', requireAuth, async (req, res) => {
      const requests = await requestsCollection.find({ userEmail: req.user.email }).sort({ createdAt: -1 }).toArray();
      res.send(requests);
    });

    app.get('/requests/pet/:petId', requireAuth, async (req, res) => {
      if (!ObjectId.isValid(req.params.petId)) return res.status(400).send({ message: 'Invalid pet id' });

      const pet = await petsCollection.findOne({ _id: new ObjectId(req.params.petId), ownerEmail: req.user.email });
      if (!pet) return res.status(403).send({ message: 'Only the owner can view requests' });

      const requests = await requestsCollection.find({ petId: req.params.petId }).sort({ createdAt: -1 }).toArray();
      res.send(requests);
    });

    app.patch('/requests/:id/status', requireAuth, async (req, res) => {
      if (!ObjectId.isValid(req.params.id)) return res.status(400).send({ message: 'Invalid request id' });

      const { status } = req.body;
      if (!['approved', 'rejected'].includes(status)) return res.status(400).send({ message: 'Invalid status' });

      const request = await requestsCollection.findOne({ _id: new ObjectId(req.params.id) });
      if (!request) return res.status(404).send({ message: 'Request not found' });

      const pet = await petsCollection.findOne({ _id: new ObjectId(request.petId), ownerEmail: req.user.email });
      if (!pet) return res.status(403).send({ message: 'Only the owner can handle this request' });
      if (request.status !== 'pending') return res.status(409).send({ message: 'This request was already handled' });
      if (status === 'approved' && pet.status === 'adopted') {
        return res.status(409).send({ message: 'Another request was already approved' });
      }

      await requestsCollection.updateOne({ _id: request._id }, { $set: { status, updatedAt: new Date() } });
      if (status === 'approved') {
        await petsCollection.updateOne({ _id: pet._id }, { $set: { status: 'adopted', updatedAt: new Date() } });
        await requestsCollection.updateMany(
          { petId: request.petId, _id: { $ne: request._id }, status: 'pending' },
          { $set: { status: 'rejected', updatedAt: new Date() } }
        );
      }

      res.send({ message: `Request ${status}` });
    });

    app.delete('/requests/:id', requireAuth, async (req, res) => {
      if (!ObjectId.isValid(req.params.id)) return res.status(400).send({ message: 'Invalid request id' });

      const result = await requestsCollection.deleteOne({ _id: new ObjectId(req.params.id), userEmail: req.user.email });
      if (!result.deletedCount) return res.status(403).send({ message: 'Only the requester can cancel this request' });
      res.send({ message: 'Request cancelled' });
    });

    await client.db('admin').command({ ping: 1 });
    console.log('Successfully connected to MongoDB!');

    app.listen(port, () => {
      console.log(`PetNest server listening on port ${port}`);
    });
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error);
    process.exit(1);
  }
}

run();