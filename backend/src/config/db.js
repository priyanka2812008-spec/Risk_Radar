import mongoose from 'mongoose';

let isConnected = false;
let dbHost = null;

export const connectDB = async () => {
  const mongoUri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/riskradar';
  try {
    const conn = await mongoose.connect(mongoUri, {
      serverSelectionTimeoutMS: 10000,
    });
    isConnected = true;
    dbHost = `${conn.connection.host}/${conn.connection.name}`;
    console.log(`[RISK RADAR DB] Connected to MongoDB: ${dbHost}`);
  } catch (error) {
    console.warn(`[RISK RADAR DB] MongoDB connection failed (${error.message}). Running with in-memory resilient state.`);
    isConnected = false;
    dbHost = null;
  }
};

export const getDBStatus = () => isConnected;
export const getDBHost = () => dbHost;

