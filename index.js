const express = require('express')
const dotenv = require('dotenv')
const cors = require('cors')
const { MongoClient, ServerApiVersion } = require('mongodb');

dotenv.config()

const app = express()
const port = process.env.PORT || 8080
const uri = process.env.MONGODB_URI

app.use(cors())
app.use(express.json())

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



app.get('/', (req, res) => {
  res.send('Petnest server is running')
})

async function run() {
  try {
    await client.connect();
    const db = client.db('petnest')
    const petsCollection = db.collection('pets')

    app.get('/pets', async (req, res) => {
      try {
        const results = await petsCollection.find().toArray()
        res.send(results)
      } catch (error) {
        console.error('Failed to fetch pets:', error.message)
        res.status(500).send({ message: 'Failed to fetch pets' })
      }
    });

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
