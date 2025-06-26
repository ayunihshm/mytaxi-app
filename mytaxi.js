const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');
require('dotenv').config();
const { authenticate, authorize } = require('./auth');

const app = express();
const port = process.env.PORT || 3500;
app.use(express.json());

let db;

// Connect to MongoDB
async function connectToMongoDB() {
  const uri = process.env.MONGODB_URI;
  const client = new MongoClient(uri);
  try {
    await client.connect();
    console.log('Connected to MongoDB!');
    db = client.db(process.env.MONGODB_DB);
  } catch (err) {
    console.error('MongoDB connection error:', err);
  }
}
connectToMongoDB();

// ========= Registration Routes ==========
app.post('/auth/register-passenger', async (req, res) => {
  const { email, password, name, phone } = req.body;
  const existing = await db.collection('passengers').findOne({ email });
  if (existing) return res.status(400).json({ error: 'Email already in use' });

  const hashed = await bcrypt.hash(password, 10);
  const result = await db.collection('passengers').insertOne({ email, password: hashed, name, phone });
  res.status(201).json({ message: 'Passenger registered', userId: result.insertedId });
});

app.post('/auth/register-driver', async (req, res) => {
  const { email, password, name, phone, carModel, licensePlate } = req.body;
  const existing = await db.collection('drivers').findOne({ email });
  if (existing) return res.status(400).json({ error: 'Email already in use' });

  const hashed = await bcrypt.hash(password, 10);
  const result = await db.collection('drivers').insertOne({
    email, password: hashed, name, phone, carModel, licensePlate,
    status: 'unavailable', approvalStatus: 'pending'
  });
  res.status(201).json({ message: 'Driver registered', userId: result.insertedId });
});

app.post('/auth/register-admin', async (req, res) => {
  const { email, password, name } = req.body;
  const existing = await db.collection('admins').findOne({ email });
  if (existing) return res.status(400).json({ error: 'Email already in use' });

  const hashed = await bcrypt.hash(password, 10);
  const result = await db.collection('admins').insertOne({ email, password: hashed, name });
  res.status(201).json({ message: 'Admin registered', adminId: result.insertedId });
});

// ===== Login Route ======
app.post('/auth/login', async (req, res) => {
  const email = req.body.email.toLowerCase();
  const { password } = req.body;
  let user, role;

  for (const r of ['drivers', 'passengers', 'admins']) {
    user = await db.collection(r).findOne({ email });
    if (user) { role = r.slice(0, -1); break; }
  }

  if (!user) return res.status(404).json({ error: 'User not found' });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ userId: user._id.toString(), role }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ message: 'Login successful', token });
});

// ====== Ride Request ======
app.post('/rides', authenticate, async (req, res) => {
  const { origin, destination, fare } = req.body;
  if (req.user.role !== 'passenger') {
    return res.status(403).json({ error: 'Only passengers can request rides' });
  }

  if (!origin || !destination || !fare) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const passenger = await db.collection('passengers').findOne({ _id: new ObjectId(req.user.userId) });
  if (!passenger) return res.status(404).json({ error: 'Passenger not found' });

  const drivers = await db.collection('drivers').find({ status: 'available', approvalStatus: 'approved' }).toArray();
  if (!drivers.length) return res.status(400).json({ error: 'No available drivers' });

  const driver = drivers[Math.floor(Math.random() * drivers.length)];

  const ride = await db.collection('rides').insertOne({
    passengerId: new ObjectId(req.user.userId),
    driverId: driver._id,
    origin,
    destination,
    fare,
    status: 'assigned',
    timestamp: new Date()
  });

  await db.collection('drivers').updateOne({ _id: driver._id }, { $set: { status: 'on-ride' } });

  res.status(201).json({ message: 'Ride requested', rideId: ride.insertedId });
});

// ===== Cancel Ride ======
app.patch('/rides/:rideId/cancel', authenticate, async (req, res) => {
  const { rideId } = req.params;
  const passengerId = req.user.userId;

  if (req.user.role !== 'passenger') {
    return res.status(403).json({ error: 'Only passengers can cancel rides' });
  }

  const ride = await db.collection('rides').findOne({
    _id: new ObjectId(rideId),
    passengerId: new ObjectId(passengerId)
  });

  if (!ride) {
    return res.status(404).json({ error: 'Ride not found or not your ride' });
  }

  if (ride.status !== 'assigned') {
    return res.status(400).json({ error: `Cannot cancel ride with status ${ride.status}` });
  }

  await db.collection('rides').updateOne({ _id: ride._id }, { $set: { status: 'cancelled' } });
  await db.collection('drivers').updateOne({ _id: ride.driverId }, { $set: { status: 'available' } });

  res.json({ message: 'Ride cancelled successfully' });
});

// ======== Update Ride Status ==========
app.patch('/rides/:rideId/status', authenticate, async (req, res) => {
  const { rideId } = req.params;
  const { status } = req.body;
  const allowedStatuses = ['accepted', 'rejected', 'completed'];

  if (!allowedStatuses.includes(status)) {
    return res.status(400).json({ error: 'Invalid status. Allowed: accepted, rejected, completed' });
  }

  if (req.user.role !== 'driver') {
    return res.status(403).json({ error: 'Only drivers can update ride status' });
  }

  const ride = await db.collection('rides').findOne({
    _id: new ObjectId(rideId),
    driverId: new ObjectId(req.user.userId)
  });

  if (!ride) return res.status(404).json({ error: 'Ride not found or not assigned to this driver' });

  if (ride.status === 'completed') {
    return res.status(400).json({ error: 'Cannot update a completed ride' });
  }

  // === ACCEPTED ===
  if (status === 'accepted') {
    if (ride.status !== 'assigned') {
      return res.status(400).json({ error: 'Only assigned rides can be accepted' });
    }
    await db.collection('rides').updateOne({ _id: ride._id }, { $set: { status: 'accepted' } });
    await db.collection('drivers').updateOne({ _id: ride.driverId }, { $set: { status: 'on-ride' } });

  // === REJECTED ===
  } else if (status === 'rejected') {
    if (ride.status !== 'assigned') {
      return res.status(400).json({ error: 'Only assigned rides can be rejected' });
    }

    // Set rejecting driver back to available
    await db.collection('drivers').updateOne({ _id: ride.driverId }, { $set: { status: 'available' } });

    // Find a new available and approved driver (excluding the current one)
    const newDriver = await db.collection('drivers').findOne({
      _id: { $ne: ride.driverId },
      status: 'available',
      approvalStatus: 'approved'
    });

    if (!newDriver) {
      // No replacement found, mark ride as rejected
      await db.collection('rides').updateOne({ _id: ride._id }, { $set: { status: 'rejected' } });
      return res.json({ message: 'Ride rejected and no available drivers. Ride marked as rejected.' });
    }

    // Reassign ride to new driver
    await db.collection('rides').updateOne({ _id: ride._id }, {
      $set: {
        driverId: newDriver._id,
        status: 'assigned'
      }
    });

    // Set new driver to on-ride
    await db.collection('drivers').updateOne({ _id: newDriver._id }, { $set: { status: 'on-ride' } });

    return res.json({ message: 'Ride reassigned to a new driver', newDriverId: newDriver._id });
  
  // === COMPLETED ===
  } else if (status === 'completed') {
    if (!['accepted', 'started'].includes(ride.status)) {
      return res.status(400).json({ error: 'Only accepted rides can be completed' });
    }
    await db.collection('rides').updateOne({ _id: ride._id }, { $set: { status: 'completed' } });
    await db.collection('drivers').updateOne({ _id: ride.driverId }, { $set: { status: 'available' } });
  }

  res.json({ message: `Ride status updated to ${status}` });
});

// ========= Driver Availability ==========
app.patch('/drivers/:id/availability', authenticate, async (req, res) => {
  const driverId = req.params.id;
  const { availabilityStatus } = req.body;

  const validStatuses = ['available', 'unavailable', 'on-ride'];
  if (!validStatuses.includes(availabilityStatus)) {
    return res.status(400).json({ error: 'Invalid availability status' });
  }

  if (req.user.role !== 'driver' || req.user.userId !== driverId) {
    return res.status(403).json({ error: 'Not allowed to update this driver' });
  }

  const result = await db.collection('drivers').updateOne({ _id: new ObjectId(driverId) }, { $set: { status: availabilityStatus } });
  if (result.modifiedCount === 0) return res.status(404).json({ error: 'Driver not found or no changes made' });

  res.json({ message: `Availability updated to ${availabilityStatus}` });
});

// ======== View Ride Status ========
app.get('/rides/:rideId', authenticate, async (req, res) => {
  const { rideId } = req.params;
  const ride = await db.collection('rides').findOne({ _id: new ObjectId(rideId) });
  if (!ride) return res.status(404).json({ error: 'Ride not found' });

  const isPassenger = ride.passengerId.toString() === req.user.userId;
  const isDriver = ride.driverId?.toString() === req.user.userId;
  if (!isPassenger && !isDriver && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized access' });
  }

  res.json(ride);
});

// ==== Rate Ride =====
app.post('/rides/:rideId/rate', authenticate, async (req, res) => {
  if (req.user.role !== 'passenger') return res.status(403).json({ error: 'Only passengers can rate rides' });

  const { rideId } = req.params;
  const { rating, comment } = req.body;
  if (!rating || rating < 1 || rating > 5) return res.status(400).json({ error: 'Rating must be between 1 and 5' });

  const ride = await db.collection('rides').findOne({ _id: new ObjectId(rideId) });
  if (!ride) return res.status(404).json({ error: 'Ride not found' });
  if (ride.passengerId.toString() !== req.user.userId) return res.status(403).json({ error: 'You can only rate your own ride' });
  if (ride.status !== 'completed') return res.status(400).json({ error: 'You can only rate completed rides' });

  await db.collection('rides').updateOne({ _id: ride._id }, { $set: { rating, comment } });
  res.json({ message: 'Ride rated successfully' });
});

// ============ Get Assigned Rides (Driver) ===============
app.get('/rides/assigned', authenticate, async (req, res) => {
  if (req.user.role !== 'driver') return res.status(403).json({ error: 'Only drivers can view assigned rides' });

  const driverId = req.user.userId;
  if (!driverId || !ObjectId.isValid(driverId)) return res.status(400).json({ error: 'Invalid or missing driver ID' });

  try {
    const rides = await db.collection('rides').find({
      driverId: new ObjectId(driverId),
      status: { $in: ['assigned', 'started'] }
    }).toArray();

    res.json({ rides });
  } catch (err) {
    console.error('Error fetching assigned rides:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ====== Ride History ======
app.get('/history', authenticate, async (req, res) => {
  const field = req.user.role === 'driver' ? 'driverId' : 'passengerId';
  const query = { [field]: new ObjectId(req.user.userId) };

  if (req.query.status) {
    query.status = req.query.status;  // e.g., 'completed'
  }

  try {
    const rides = await db.collection('rides').find(query).toArray();
    res.json({ rides });
  } catch (err) {
    console.error('Error fetching ride history:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ====== Admin Routes ======
app.get('/admin/users', authenticate, authorize(['admin']), async (req, res) => {
  const passengers = await db.collection('passengers').find().toArray();
  const drivers = await db.collection('drivers').find().toArray();
  res.json({ passengers, drivers });
});

app.patch('/admin/approve/:id', authenticate, authorize(['admin']), async (req, res) => {
  const driverId = req.params.id;
  const update = await db.collection('drivers').updateOne({ _id: new ObjectId(driverId) }, { $set: { approvalStatus: 'approved' } });
  if (update.matchedCount === 0) return res.status(404).json({ error: 'Driver not found' });
  res.json({ message: 'Driver approved' });
});

// Start server
app.listen(port, () => console.log(`MyTaxi Server running on port ${port}`));

// Azure App
app.get('/', (req, res) => {
  res.send('MyTaxi API is running on Azure!');
});
