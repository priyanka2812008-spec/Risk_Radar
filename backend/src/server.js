import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { connectDB, getDBStatus, getDBHost } from './config/db.js';
import { initSeedData } from './store/riskStore.js';
import scanRoutes from './routes/scanRoutes.js';
import watchlistRoutes from './routes/watchlistRoutes.js';
import reportRoutes from './routes/reportRoutes.js';
import socRoutes from './routes/socRoutes.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Health Check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ONLINE',
    service: 'Risk Radar Intelligence Backend',
    version: '4.2.1-SOC',
    database: getDBStatus() ? 'mongodb' : 'memory',
    host: getDBHost(),
    timestamp: new Date().toISOString()
  });
});

// Mount Routes
app.use('/api', scanRoutes);
app.use('/api', watchlistRoutes);
app.use('/api', reportRoutes);
app.use('/api', socRoutes);

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ error: `Route ${req.originalUrl} not found.` });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('[RISK RADAR ERROR]', err);
  res.status(500).json({ error: 'Internal server error: ' + err.message });
});

// Server Initialization
const startServer = async () => {
  try {
    await connectDB();
    await initSeedData();

    app.listen(PORT, () => {
      console.log(`\n======================================================`);
      console.log(`🛡️  RISK RADAR CYBERSECURITY PLATFORM ACTIVE`);
      console.log(`📡  Backend Server running on: http://localhost:${PORT}`);
      console.log(`🔍  Engine Health: http://localhost:${PORT}/api/health`);
      console.log(`======================================================\n`);
    });
  } catch (err) {
    console.error('Failed to initialize server:', err);
    process.exit(1);
  }
};

startServer();
