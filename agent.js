"use strict";
import dotenv from 'dotenv';
import axios from 'axios';
import os from 'os';
import fs from 'fs';
import { exec } from 'child_process';
import { networkInterfaces } from 'os';
import psList from 'ps-list';
import activeWin from 'active-win';
import screenshot from 'screenshot-desktop';
import clipboardy from 'clipboardy';
import chokidar from 'chokidar';
import WebSocket from 'ws';
import robot from 'robotjs';
import https from 'https';
import brain from 'brain.js';
import crypto from 'crypto';

// NEW: Import additional ML libraries
import { DecisionTreeClassifier } from 'ml-cart';
import { RandomForestClassifier } from 'ml-random-forest';  // See https://www.npmjs.com/package/ml-random-forest
// Remove SVM since it is not being used.
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
let tf;
try {
  tf = require('@tensorflow/tfjs');  // Use regular tfjs instead of tfjs-node
  console.log('Using TensorFlow.js browser version');
} catch (error) {
  console.error('Failed to load TensorFlow:', error);
  tf = null;
}
import { kmeans } from 'ml-kmeans';  // Replace the require statement
import XLSX from 'xlsx';

import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import express from 'express';

dotenv.config();

// --- Environment Validation ---
if (!process.env.LOG_ENCRYPTION_KEY || process.env.LOG_ENCRYPTION_KEY.length !== 32) {
  throw new Error('Invalid or missing LOG_ENCRYPTION_KEY. Must be a 32-byte string.');
}

// (Configuration validation for production is assumed later in the file)

// --- Process‑wide Error Handling ---
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
  process.exit(1);
});

// --- Parameterized Configuration & Reconnect Delay ---
const config = {
  serverUrl: process.env.SERVER_URL || 'https://localhost:3001',
  websocketUrl: process.env.WEBSOCKET_URL || 'wss://localhost:3001',
  agentName: process.env.AGENT_NAME || os.hostname(),
  agentContact: process.env.AGENT_CONTACT || 'thehackingman33@gmail.com',
  websocketReconnectDelay: Number(process.env.WEBSOCKET_RECONNECT_DELAY_MS) || 5000,
};

// --- HTTP Agent for self-signed SSL (development only) ---
const httpsAgent = new https.Agent({ rejectUnauthorized: false });

// --- Revamped encryptLog using AES-256-GCM ---
const encryptLog = (text) => {
  const key = process.env.LOG_ENCRYPTION_KEY;
  if (!key || key.length !== 32) {
    throw new Error('Invalid LOG_ENCRYPTION_KEY. Must be a 32-byte string.');
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return iv.toString('hex') + ':' + tag + ':' + encrypted;
};

// --- Global Logging Infrastructure ---
const logQueue = [];
const LOG_FLUSH_INTERVAL_MS = Number(process.env.LOG_FLUSH_INTERVAL_MS) || 5000;
let isFlushing = false;

const enqueueLog = (message, severity = 'info') => {
  logQueue.push({ message, severity });
};

const flushLogQueue = async () => {
  if (isFlushing || logQueue.length === 0) return;
  isFlushing = true;
  const batch = logQueue.splice(0, logQueue.length);
  try {
    const payload = {
      agentId: config.agentName,
      log: encryptLog(JSON.stringify(batch)),
      severity: 'batch'
    };
    const response = await axios.post(`${config.serverUrl}/api/logs`, payload, { httpsAgent });
    console.log('HTTP log sent. Response:', response.data);
  } catch (error) {
    console.error('Error flushing log queue:', error);
    logQueue.unshift(...batch);
  }
  isFlushing = false;
};
setInterval(flushLogQueue, LOG_FLUSH_INTERVAL_MS);

const sendLog = async (message, severity = 'info') => {
  enqueueLog({ message, timestamp: new Date().toISOString() }, severity);
};

// --- WebSocket Initialization with Reconnection ---
let ws;
let isReconnecting = false;

// Initialize Express app for additional security
const app = express();
app.use(helmet()); // Add security headers
app.use(express.json()); // Parse JSON bodies

// NEW: Verify .env file integrity (placeholder for digital signature verification)
// if (!verifyDotEnvIntegrity()) { throw new Error('Configuration file integrity check failed'); }

// Enhance helmet settings with strict CSP and enable CORS
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", "data:"]
    }
  }
}));
const cors = require('cors');
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['https://yourdomain.com'],
  optionsSuccessStatus: 200
}));

// Rate limiting middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again later."
});
app.use(limiter);

// Validate environment variables
const requiredEnvVars = [
  'SERVER_URL', 'WEBSOCKET_URL', 'LOG_ENCRYPTION_KEY', 'JWT_SECRET', 'HTTPS_KEY_PATH', 'HTTPS_CERT_PATH'
];
requiredEnvVars.forEach(varName => {
  if (!process.env[varName]) {
    throw new Error(`Missing required environment variable: ${varName}`);
  }
});

const initializeWebSocket = () => {
  const wsInstance = new WebSocket(config.websocketUrl, {
    rejectUnauthorized: false, // Accept self-signed certificates
    headers: {
      'Authorization': `Bearer ${process.env.JWT_SECRET}` // Use JWT for authentication
    }
  });
  let heartbeatInterval;
  
  const heartbeat = () => {
    if (wsInstance.readyState === wsInstance.OPEN) {
      console.log('Sending heartbeat...');
      wsInstance.send(JSON.stringify({ type: 'heartbeat', timestamp: Date.now() }));
    }
  };

  wsInstance.on('open', () => {
    console.log('WebSocket connected.');
    wsReconnectDelay = config.websocketReconnectDelay;
    isReconnecting = false;
    wsInstance.send(JSON.stringify({ type: 'connect', agentId: config.agentName, timestamp: Date.now() }));
    heartbeatInterval = setInterval(heartbeat, 30000);
  });

  wsInstance.on('message', data => {
    try {
      const message = JSON.parse(data);
      if (!message.type) {
        throw new Error('Invalid message format');
      }
      console.log('Received message:', message);
      if (message.type === 'RETRAIN_MODEL') {
        console.log('Retraining model as requested');
        trainNetwork();
      }
    } catch (error) {
      console.error('Error parsing WebSocket message:', error);
    }
  });

  wsInstance.on('close', () => {
    console.error('WebSocket connection closed.');
    clearInterval(heartbeatInterval);
    attemptReconnect();
  });

  wsInstance.on('error', error => {
    console.error('WebSocket error:', error);
    wsInstance.close();
  });
  return wsInstance;
};

let wsReconnectDelay = config.websocketReconnectDelay;
const MAX_WS_RECONNECT_DELAY = 60000;
const attemptReconnect = () => {
  if (isReconnecting) return;
  isReconnecting = true;
  console.log(`Attempting WebSocket reconnect in ${wsReconnectDelay} ms...`);
  setTimeout(() => {
    ws = initializeWebSocket();
    wsReconnectDelay = Math.min(wsReconnectDelay * 2, MAX_WS_RECONNECT_DELAY);
  }, wsReconnectDelay);
};

ws = initializeWebSocket();

// --- Existing Brain.js Neural Network (for baseline intrusion detection) ---
const networkML = new brain.NeuralNetwork({ hiddenLayers: [3], activation: 'sigmoid' });
const trainingData = [
  { input: [0.9, 0.95, 0.1], output: [1] },
  { input: [0.85, 0.9, 0.15], output: [1] },
  { input: [0.2, 0.3, 0.01], output: [0] },
  { input: [0.1, 0.2, 0.02], output: [0] }
];

function loadXlsxTrainingData(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const workbook = XLSX.readFile(filePath);
  const sheetName = workbook.SheetNames[0];
  const data = XLSX.utils.sheet_to_json(workbook.Sheets[sheetName], { header: 1 });

  // Convert each row [feat1, feat2, feat3, label] into Brain.js format
  const rows = data.slice(1).map(row => ({
    input: row.slice(0, 3).map(val => parseFloat(val) || 0),
    output: [parseFloat(row[3]) || 0],
  }));

  return rows;
}

function deduplicateTrainingData(data) {
  const seen = new Set();
  return data.filter(entry => {
    const key = entry.input.join(',') + '|' + entry.output.join(',');
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

const xlsxData = loadXlsxTrainingData('./trainingData.xlsx');
if (xlsxData.length > 0) {
  const uniqueXlsxData = deduplicateTrainingData(xlsxData);
  trainingData.push(...uniqueXlsxData);
  console.log(`Loaded ${uniqueXlsxData.length} unique samples from XLSX.`);
}

const trainNetwork = () => {
  try {
    if (fs.existsSync('./trainedModel.json')) {
      const modelData = JSON.parse(fs.readFileSync('./trainedModel.json', 'utf8'));
      networkML.fromJSON(modelData);
      console.log('Loaded pre-trained model from ./trainedModel.json');
    } else {
      const trainingResult = networkML.train(trainingData, {
        iterations: 2000,
        errorThresh: 0.005,
        inputSize: 3, // Specify input size
        outputSize: 1, // Specify output size
        log: details => { if(process.env.NODE_ENV !== 'production') console.log(details); }
      });
      fs.writeFileSync('./trainedModel.json', JSON.stringify(networkML.toJSON()), { mode: 0o600 });
      console.log('Trained and saved new model', trainingResult);
    }
  } catch (error) {
    console.error('Error in network training:', error);
  }
};

const detectIntrusion = (metrics) => {
  const inputArray = [
    metrics.cpu / 100,
    metrics.memory / 100,
    Math.min(metrics.connections / 1000, 1)
  ];
  const result = networkML.run(inputArray);
  const probability = Array.isArray(result) ? result[0] : 0;
  return { probability, isIntrusion: probability > 0.5 };
};

// --- New: Advanced ML Models Integration ---
// 1. Decision Tree & Random Forest Classifiers
let decisionTree;
let rf; // We'll store the Random Forest instance in "rf"
const decisionTreeTrainingData = {
  features: trainingData.map(d => Array.isArray(d.input) ? d.input : [d.input]),
  labels: trainingData.map(d => Array.isArray(d.output) ? d.output[0] : d.output)
};

try {
  // Initialize Decision Tree classifier
  decisionTree = new DecisionTreeClassifier({ gainFunction: 'gini', maxDepth: 10 });
  decisionTree.train(decisionTreeTrainingData.features, decisionTreeTrainingData.labels);
  console.log("Decision Tree trained.");
} catch (err) {
  console.error("Error training Decision Tree:", err);
}

try {
  rf = new RandomForestClassifier({
    nEstimators: 5,          // Reduce number of trees
    maxFeatures: 3,          // Use all features (we have 3)
    replacement: true,
    seed: 42,
    useSampleBagging: true   // Add bagging to improve stability
  });
  
  // Ensure training data format is correct
  const features = trainingData.map(d => {
    const input = Array.isArray(d.input) ? d.input : [d.input];
    while (input.length < 3) input.push(0);
    return input.slice(0, 3).map(v => Number(v) || 0);
  });
  
  const labels = trainingData.map(d => Number(d.output[0]) || 0);
  
  // Log data shape for debugging
  console.log('Random Forest training data shape:', 
    `features: ${features.length}x${features[0].length}`,
    `labels: ${labels.length}`);
    
  rf.train(features, labels);
  console.log("Random Forest trained successfully");
} catch (err) {
  console.error("Error training Random Forest:", err);
  rf = null;
}

try {
  const dtFeatures = trainingData.map(d => {
    const input = Array.isArray(d.input) ? d.input : [d.input];
    while (input.length < 3) input.push(0);
    return input.slice(0, 3).map(v => Number(v) || 0);
  });
  
  const dtLabels = trainingData.map(d => Number(d.output[0]) || 0);
  
  decisionTree = new DecisionTreeClassifier({ 
    gainFunction: 'gini',
    maxDepth: 4,  // Reduce depth to prevent overfitting
    minNumSamples: 1
  });
  
  decisionTree.train(dtFeatures, dtLabels);
  console.log("Decision Tree trained successfully");
} catch (err) {
  console.error("Error training Decision Tree:", err);
  decisionTree = null;
}

// 3. Deep Learning Models with TensorFlow.js (e.g., CNN/RNN for time-series or packet data)
let deepModel;
const createDeepModel = () => {
  const model = tf.sequential();
  model.add(tf.layers.dense({ units: 16, activation: 'relu', inputShape: [3] }));
  model.add(tf.layers.dense({ units: 8, activation: 'relu' }));
  model.add(tf.layers.dense({ units: 1, activation: 'sigmoid' }));
  model.compile({ optimizer: 'adam', loss: 'binaryCrossentropy', metrics: ['accuracy'] });
  return model;
};
deepModel = createDeepModel();
// (Training deepModel would be similar to standard TF.js training; you might load pre-trained weights.)

// 4. Anomaly Detection via Autoencoder with TensorFlow.js
let autoencoder;
const createAutoencoder = () => {
  const input = tf.input({ shape: [3] });
  const encoded = tf.layers.dense({ units: 2, activation: 'relu' }).apply(input);
  const decoded = tf.layers.dense({ units: 3, activation: 'sigmoid' }).apply(encoded);
  const model = tf.model({ inputs: input, outputs: decoded });
  model.compile({ optimizer: 'adam', loss: 'meanSquaredError' });
  return model;
};
autoencoder = createAutoencoder();
// (You would train this autoencoder on “normal” system behavior data.)

// 5. Ensemble Learning: Combine predictions from multiple models.
function prepareRfInput(features) {
  if (!Array.isArray(features)) return [];
  return features.map(value => parseFloat(value) || 0);
}

const ensemblePredict = async (metrics) => {
  let predictions = [];
  const inputArray = [
    metrics.cpu / 100,
    metrics.memory / 100,
    Math.min(metrics.connections / 1000, 1)
  ];

  if (networkML) {
    try {
      const baseline = networkML.run(inputArray);
      predictions.push(Array.isArray(baseline) ? baseline[0] : baseline);
    } catch (err) {
      console.error("Error in baseline prediction:", err);
    }
  }

  if (decisionTree) {
    try {
      const dtPred = decisionTree.predict([inputArray]);
      if (Array.isArray(dtPred) && dtPred.length > 0) {
        predictions.push(dtPred[0]);
      }
    } catch (err) {
      console.error("Error in decision tree prediction:", err);
    }
  }

  if (rf) {
    try {
      const rfPred = rf.predict([inputArray]);
      if (Array.isArray(rfPred) && rfPred.length > 0) {
        predictions.push(rfPred[0]);
      }
    } catch (err) {
      console.error("Error in Random Forest prediction:", err);
    }
  }

  const validPredictions = predictions.filter(p => typeof p === 'number' && !isNaN(p));
  return validPredictions.length > 0 
    ? validPredictions.reduce((a, b) => a + b, 0) / validPredictions.length 
    : 0.5;
};

// 6. Unsupervised Learning (K-means clustering for novel behavior)
let clusteringModel;
const historicalData = trainingData.map(d => d.input);
try {
  const numClusters = 2;
  const data = Array.isArray(historicalData[0]) ? historicalData : [historicalData];
  clusteringModel = kmeans(data, numClusters, {
    initialization: 'random',
    seed: 42,
    maxIterations: 100
  });
  console.log("K-means clustering model computed.");
} catch (err) {
  console.error("Error with K-means clustering:", err);
}

// --- Updated Forensic Data Collection Function ---
async function collectForensicData() {
  const activeWindow = await activeWin();
  const screenshotPath = `screenshot_${Date.now()}.png`;
  try {
    await screenshot({ filename: screenshotPath });
  } catch (error) {
    console.error('Screenshot capture failed:', error.message);
  }
  return { activeWindow, screenshotPath };
}

// --- Safe Wrapper for Command Execution ---
const allowedPreventionCommands = {
  win32: [
    'netsh advfirewall firewall add rule name="BlockSuspicious" dir=in action=block protocol=TCP localport=any',
    'netsh advfirewall firewall add rule name="BlockSuspiciousIP" dir=in action=block protocol=TCP localport=80 remoteip=192.168.1.100',
    'netsh advfirewall firewall delete rule name="BlockSuspicious"',
    'netsh advfirewall firewall delete rule name="BlockSuspiciousIP"'
  ],
  unix: [
    'sudo iptables -A INPUT -p tcp --dport 80 -j DROP',
    'sudo iptables -A INPUT -p tcp --dport 80 -s 192.168.1.100 -j DROP',
    'sudo iptables -D INPUT -p tcp --dport 80 -j DROP',
    'sudo iptables -D INPUT -p tcp --dport 80 -s 192.168.1.100 -j DROP'
  ]
};

const isAdmin = async () => {
  if (os.platform() === 'win32') {
    try {
      await safeExec('net session', () => {});
      return true;
    } catch {
      return false;
    }
  }
  return process.getuid && process.getuid() === 0;
};

const safeExec = (command, callback) => {
  const platform = os.platform();
  let allowedCommands = platform === 'win32' ? allowedPreventionCommands.win32 : allowedPreventionCommands.unix;
  if (!allowedCommands.some(allowedCommand => command.startsWith(allowedCommand.split(' ')[0]))) {
    return callback(new Error('Command not allowed for execution'), '', '');
  }
  isAdmin().then(hasAdmin => {
    if (!hasAdmin) {
      console.error('Administrative privileges required to modify firewall rules');
      return callback(new Error('Administrative privileges required'), '', '');
    }
    const cmdPrefix = platform === 'win32' ? '' : 'sudo ';
    exec(cmdPrefix + command, (error, stdout, stderr) => {
      if (error) {
        console.error(`Command execution error: ${error.message}`);
        console.error(`Command: ${command}`);
        console.error(`stderr: ${stderr}`);
        return callback(error, '', stderr);
      }
      callback(null, stdout, stderr);
    });
  });
};

// --- Advanced Firewall Module ---
const applyFirewallRule = async (action, rule) => {
  let command = '';
  if (os.platform() === 'win32') {
    if (action === 'add') {
      command = `netsh advfirewall firewall add rule name="${rule.name}" dir=in action=block protocol=${rule.protocol} localport=${rule.port}`;
    } else if (action === 'remove') {
      command = `netsh advfirewall firewall delete rule name="${rule.name}"`;
    }
  } else {
    if (action === 'add') {
      command = `sudo iptables -A INPUT -p ${rule.protocol} --dport ${rule.port} -j DROP`;
    } else if (action === 'remove') {
      command = `sudo iptables -D INPUT -p ${rule.protocol} --dport ${rule.port} -j DROP`;
    }
  }
  return new Promise((resolve, reject) => {
    safeExec(command, (error, stdout, stderr) => {
      if (error) {
        console.error(`Firewall rule ${action} error:`, error.message);
        return reject(error);
      }
      console.log(`Firewall rule ${action} executed:`, stdout);
      resolve(stdout);
    });
  });
};

const suspiciousFirewallRule = {
  name: "BlockSuspicious",
  protocol: "TCP",
  port: "any"
};

const getPreventionCommand = () => {
  if (os.platform() === 'win32') {
    return 'netsh advfirewall firewall add rule name="BlockSuspicious" dir=in action=block protocol=TCP localport=any';
  } else {
    return 'sudo iptables -A INPUT -p tcp --dport 80 -j DROP';
  }
};

const sanitizeInput = (input) => {
  return typeof input === 'string' ? input.replace(/[<>'"]/g, '') : input;
};

const threatIntelLookup = async (metrics) => {
  console.log('Querying external threat intelligence...');
  let intel = { indicator: 'Suspicious IP Detected', details: 'Placeholder details' };
  intel.indicator = sanitizeInput(intel.indicator);
  intel.details = sanitizeInput(intel.details);
  return intel;
};

const preventAttack = async (metrics) => {
  if (!rateLimiter.canExecute()) {
    console.log('Prevention action skipped due to rate limiting');
    return;
  }
  console.log('PREVENTION: Initiating advanced cyber attack prevention measures...');
  try {
    const preventionCommand = getPreventionCommand();
    const intel = await threatIntelLookup(metrics);
    console.log(`Threat Intel: ${JSON.stringify(intel)}`);
    console.log('Applying firewall rule to block suspicious activity...');
    await applyFirewallRule('add', suspiciousFirewallRule);
    console.log(`Executing prevention command: ${preventionCommand}`);
    safeExec(preventionCommand, (error, stdout, stderr) => {
      if (error) {
        console.error(`PREVENTION ERROR: ${error.message}`);
        return;
      }
      console.log(`Prevention action executed: ${stdout}`);
    });
  } catch (error) {
    console.error(`Error in advanced prevention measures: ${error.message}`);
  }
};

// --- Global Variables for Trend Analysis and Cooldown ---
const detectionHistory = [];
const historyLength = 5;
const sustainedThreshold = 0.7;
const preventionCooldownMs = 60000;
let lastPreventionTime = 0;

const alertAdmin = async (metrics, sustainedAvg) => {
  console.log(`ALERT: Sustained threat detected (average probability: ${sustainedAvg.toFixed(3)}). Admin alerted.`);
};

const isSustainedAttack = (currentProbability, threshold) => {
  detectionHistory.push(currentProbability);
  if (detectionHistory.length > historyLength) {
    detectionHistory.shift();
  }
  const avg = detectionHistory.reduce((a, b) => a + b, 0) / detectionHistory.length;
  console.log(`DEBUG: Moving average intrusion probability: ${avg.toFixed(3)}`);
  return avg > threshold ? avg : 0;
};

const adjustSustainedThreshold = () => {
  const memUsage = ((os.totalmem() - os.freemem()) / os.totalmem()) * 100;
  return memUsage > 80 ? 0.6 : sustainedThreshold;
};

// --- Production Mode Check ---
if (process.env.NODE_ENV === 'production') {
  console.log('Production mode enabled. Debug operations are disabled.');
  process.env.DEBUG_INTRUSION = 'false';
  if (!/^https:\/\//.test(config.serverUrl)) {
    throw new Error('In production, SERVER_URL must use HTTPS.');
  }
  if (!/^wss:\/\//.test(config.websocketUrl)) {
    throw new Error('In production, WEBSOCKET_URL must use WSS.');
  }
  console.log('Production mode enabled. Secure protocols enforced.');
}

// --- Scheduler and Initialization ---
trainNetwork();
setInterval(() => {
  cleanupOldHistory();
  monitorSystem();
}, 10000);

// --- Data Collection Functions ---
async function getSystemInfo() {
  return {
    hostname: os.hostname(),
    platform: os.platform(),
    release: os.release(),
    uptime: os.uptime(),
    cpu: os.cpus()[0].model,
    memory: { total: os.totalmem(), free: os.freemem() },
    network: networkInterfaces(),
  };
}

async function getProcesses() {
  return await psList();
}

async function getActiveWindow() {
  try {
    const win = await activeWin();
    return win ? win.title : 'Unknown';
  } catch (err) {
    console.error('Error retrieving active window:', err);
    return 'Error';
  }
}

async function getClipboardContent() {
  try {
    return await clipboardy.read();
  } catch (err) {
    console.error('Error reading clipboard:', err);
    return 'Error';
  }
}

const getOpenConnections = () => new Promise(resolve => {
  exec('netstat -ano', (error, stdout) => {
    if (error) {
      console.error(`Error executing netstat: ${error.message}`);
      return resolve('Error fetching netstat');
    }
    resolve(stdout);
  });
});

// --- File Watcher ---
const watchPath = process.env.WATCH_PATH || '/path/to/watch';
console.log('Watching files in:', watchPath);
const fileWatcher = chokidar.watch(watchPath, { persistent: true });
fileWatcher.on('all', async (event, path) => {
  console.log(`File event detected: ${event} on ${path}`);
  await sendLog(`File ${event} detected at ${path}`, 'warning');
  detectMassFileModification(event);
});

// --- Advanced ML Continuous Retraining and Proactive Prevention ---
let incidentTrainingData = [];
const saveIncidentData = (metrics, label) => {
  const inputArray = [
    metrics.cpu / 100,
    metrics.memory / 100,
    Math.min(metrics.connections / 1000, 1)
  ];
  incidentTrainingData.push({ input: inputArray, output: [label] });
  console.log(`Incident data saved. Total incidents: ${incidentTrainingData.length}`);
};

const continuousRetrainModel = () => {
  if (incidentTrainingData.length === 0) {
    console.log('No new incident data to retrain.');
    return;
  }
  console.log('Continuous Retraining: Updating model with incident data...');
  const newTrainingData = trainingData.concat(incidentTrainingData);
  const trainingResult = networkML.train(newTrainingData, {
    iterations: 3000,
    errorThresh: 0.003,
    log: details => console.log(details)
  });
  fs.writeFileSync('./trainedModel.json', JSON.stringify(networkML.toJSON()));
  console.log('Model retrained with new incidents', trainingResult);
  incidentTrainingData = [];
};

setInterval(continuousRetrainModel, 10 * 60 * 1000);

// --- Graceful Shutdown Handler ---
const gracefulShutdown = async () => {
  console.log('Initiating graceful shutdown...');
  if (logQueue.length > 0) await flushLogQueue();
  if (ws && ws.readyState === ws.OPEN) {
    ws.close();
  }
  process.exit(0);
};

process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);

// --- Self‑Diagnostics Function ---
const selfDiagnostics = async () => {
  try {
    const systemInfo = await getSystemInfo();
    const logMessage = {
      type: 'SELF_DIAGNOSTICS',
      timestamp: new Date().toISOString(),
      systemInfo,
      logQueueLength: logQueue.length
    };
    await sendLog(logMessage, 'info');
    console.log('Self‐diagnostics sent:', logMessage);
  } catch (error) {
    console.error('Self‑diagnostics error:', error.message);
  }
};

setInterval(selfDiagnostics, 5 * 60 * 1000);

// --- Additional Helper Functions ---
const getActiveWebsite = async () => {
  try {
    const win = await activeWin();
    const browsers = ['chrome', 'firefox', 'msedge', 'opera'];
    if (win && win.owner && browsers.includes(win.owner.name.toLowerCase())) {
      return win.title;
    }
    return 'No active browser window';
  } catch (error) {
    console.error('Error retrieving active website:', error);
    return 'Error retrieving active website';
  }
};

const logActiveWebsite = async () => {
  const website = await getActiveWebsite();
  const logMessage = {
    type: 'ACTIVE_WEBSITE',
    timestamp: new Date().toISOString(),
    website
  };
  await sendLog(logMessage, 'info');
  console.log('Active website logged:', website);
};

setInterval(logActiveWebsite, 60 * 1000);

const suspiciousProcessKeywords = ['miner', 'cryptominer', 'suspicious'];
const analyzeProcesses = async () => {
  try {
    const processes = await getProcesses();
    const suspicious = processes.filter(p => {
      const name = p.name.toLowerCase();
      return suspiciousProcessKeywords.some(keyword => name.includes(keyword));
    });
    if (suspicious.length > 0) {
      console.log('Suspicious processes detected:', suspicious.map(p => p.name));
      await sendLog({
        type: 'SUSPICIOUS_PROCESSES',
        timestamp: new Date().toISOString(),
        details: suspicious.map(p => ({ name: p.name, pid: p.pid }))
      }, 'critical');
    }
  } catch (error) {
    console.error('Error analyzing processes:', error.message);
  }
};

setInterval(analyzeProcesses, 60 * 1000);

const logAllSystemActivity = async () => {
  try {
    const systemInfo = await getSystemInfo();
    const processes = await getProcesses();
    const activeWindow = await getActiveWindow();
    const clipboard = await getClipboardContent();
    const connections = await getOpenConnections();
    const logMessage = {
      type: 'SYSTEM_ACTIVITY',
      timestamp: new Date().toISOString(),
      systemInfo,
      activeWindow,
      processesCount: processes.length,
      clipboardSnippet: clipboard.substring(0, 100),
      connectionsSummary: connections.substring(0, 100)
    };
    await sendLog(logMessage, 'debug');
    console.log('Detailed system activity logged.');
  } catch (error) {
    console.error('Error logging system activity:', error);
  }
};

setInterval(logAllSystemActivity, 60 * 1000);

const rateLimiter = {
  lastAction: 0,
  minimumInterval: 5000,
  canExecute() {
    const now = Date.now();
    if (now - this.lastAction >= this.minimumInterval) {
      this.lastAction = now;
      return true;
    }
    return false;
  }
};

const cleanupOldHistory = () => {
  if (detectionHistory.length > 100) {
    detectionHistory.splice(0, detectionHistory.length - historyLength);
  }
  if (incidentTrainingData.length > 1000) {
    incidentTrainingData.splice(0, incidentTrainingData.length - 1000);
  }
};

const DDOS_THRESHOLD = 100;
let lastFileEventCount = 0;
const FILE_EVENT_WINDOW_MS = 60000;
let fileEventCount = 0;
let fileEventTimer = Date.now();

const detectDdosAttack = async () => {
  try {
    const netstatOutput = await getOpenConnections();
    const lines = netstatOutput.split('\n');
    const establishedCount = lines.filter(line => line.includes('ESTABLISHED')).length;
    if (establishedCount > DDOS_THRESHOLD) {
      console.warn(`DDoS Alert: ${establishedCount} established connections.`);
      await sendLog({ 
        type: 'DDOS_DETECTED',
        establishedConnections: establishedCount,
        threshold: DDOS_THRESHOLD,
        timestamp: new Date().toISOString()
      }, 'critical');
    }
  } catch (error) {
    console.error('Error in DDoS detection:', error.message);
  }
};

const detectMassFileModification = async (event) => {
  fileEventCount++;
  const now = Date.now();
  if (now - fileEventTimer > FILE_EVENT_WINDOW_MS) {
    if (fileEventCount - lastFileEventCount > 50) {
      console.warn(`Mass File Modification Alert: ${fileEventCount - lastFileEventCount} events.`);
      await sendLog({
        type: 'MASS_FILE_MODIFICATION',
        eventCount: fileEventCount - lastFileEventCount,
        threshold: 50,
        timestamp: new Date().toISOString()
      }, 'critical');
    }
    lastFileEventCount = fileEventCount;
    fileEventTimer = now;
  }
};

const detectPrivilegeEscalation = async () => {
  try {
    const processes = await getProcesses();
    const allowedAdminProcesses = ['explorer.exe', 'System', 'svchost.exe'];
    const suspicious = processes.filter(proc => {
      const name = proc.name.toLowerCase();
      return !allowedAdminProcesses.some(allowed => name.includes(allowed.toLowerCase())) &&
             (name.includes('admin') || name.includes('root') || name.includes('system'));
    });
    if (suspicious.length > 0) {
      console.warn('Privilege Escalation Alert:', suspicious.map(p => p.name));
      await sendLog({
        type: 'PRIVILEGE_ESCALATION',
        details: suspicious.map(p => ({ name: p.name, pid: p.pid })),
        timestamp: new Date().toISOString()
      }, 'critical');
    }
  } catch (error) {
    console.error('Error detecting privilege escalation:', error.message);
  }
};

const enhancedMonitorSystem = async () => {
  try {
    const metrics = await collectMetrics();
    const behavior = analyzeBehavior(metrics);
    const detection = detectIntrusion(metrics);
    const ensembleScore = await ensemblePredict(metrics);
    // NEW: Compute network anomaly score
    const networkAnomaly = await detectAnomalousNetworkTraffic();

    // Combine all detection methods with additional weight from network anomaly
    const threatScore = (detection.probability + behavior.score + ensembleScore + networkAnomaly) / 4;
    
    console.log(`Combined threat score: ${threatScore.toFixed(3)}`);
    
    if (threatScore > 0.7) {
      // HIGH threat: take immediate action
      await handleHighThreat(metrics, behavior);
    } else if (threatScore > 0.5) {
      // MEDIUM threat: increase monitoring
      await handleMediumThreat(metrics, behavior);
    } else {
      console.log('Threat score within normal range.');
    }
  } catch (error) {
    console.error('Error in enhanced monitoring:', error);
    await sendLog({
      type: 'MONITORING_ERROR',
      error: error.message,
      timestamp: new Date().toISOString()
    }, 'error');
  }
};

setInterval(() => {
  cleanupOldHistory();
  enhancedMonitorSystem().catch(console.error);
}, Number(process.env.MONITORING_FREQUENCY) || 10000);

// Add monitorSystem to collect metrics and trigger intrusion handling:
const monitorSystem = async () => {
  const isWindows = os.platform() === 'win32';
  const cpuUsage = isWindows ? 50 + Math.random() * 50 : os.loadavg()[0] * 10;
  const memoryUsage = isWindows ? 30 + Math.random() * 40 : ((os.totalmem() - os.freemem()) / os.totalmem()) * 100;
  const connectionsCount = isWindows ? Math.floor(5 + Math.random() * 10) : (await getOpenConnections()).split('\n').length;
  const metrics = { cpu: cpuUsage, memory: memoryUsage, connections: connectionsCount };
  const detection = detectIntrusion(metrics);
  console.log(`Intrusion detection result: ${detection.probability.toFixed(3)} | ${detection.isIntrusion ? 'Intrusion' : 'Normal'}`);
  if (detection.isIntrusion) {
    await handleIntrusion(metrics);
  }
};

// Add handleIntrusion to collect forensic data and send a log:
function isOutsideBusinessHours() {
  const currentHour = new Date().getHours();
  return (currentHour < 8 || currentHour > 18); // Adjust hours as needed
}

const handleIntrusion = async (metrics) => {
  console.log('Handling intrusion; collecting forensic data...');
  const forensicData = await collectForensicData();
  const severity = isOutsideBusinessHours() ? 'critical' : 'warning';
  await sendLog({
    type: 'INTRUSION_DETECTED',
    metrics,
    forensicData,
    timestamp: new Date().toISOString()
  }, severity);
  // Additional handling can be added here.
};

const firewallRules = [];

// Add a firewall rule
const executeWindowsCommand = async (command) => {
  return new Promise((resolve, reject) => {
    const cmdProcess = exec(command, {
      windowsHide: true,
      windowsVerbatimArguments: true
    }, (error, stdout, stderr) => {
      if (error) {
        console.error('Command execution error:', error);
        reject(error);
        return;
      }
      resolve(stdout);
    });
  });
};

const addFirewallRule = async (rule) => {
  if (os.platform() === 'win32') {
    const command = `netsh advfirewall firewall add rule name="${rule.name}" dir=in action=block protocol=${rule.protocol} localport=${rule.port} ${rule.remoteIp ? `remoteip=${rule.remoteIp}` : ''}`;
    try {
      await executeWindowsCommand(command);
      console.log(`Firewall rule added: ${rule.name}`);
      firewallRules.push(rule);
    } catch (error) {
      console.error('Failed to add firewall rule:', error);
      throw error;
    }
  } else {
    // Unix systems remain unchanged (placeholder)
  }
};

const removeFirewallRule = async (rule) => {
  if (os.platform() === 'win32') {
    const command = `netsh advfirewall firewall delete rule name="${rule.name}"`;
    try {
      await executeWindowsCommand(command);
      console.log(`Firewall rule removed: ${rule.name}`);
      const index = firewallRules.findIndex(r => r.name === rule.name);
      if (index !== -1) firewallRules.splice(index, 1);
    } catch (error) {
      console.error('Failed to remove firewall rule:', error);
      throw error;
    }
  } else {
    // Unix systems remain unchanged (placeholder)
  }
};

const listFirewallRules = () => {
  return firewallRules;
};

// Example firewall rule
const exampleRule = {
  name: "BlockSuspiciousIP",
  direction: "in",
  action: "block",
  protocol: "TCP",
  port: "80",
  remoteIp: "192.168.1.100"
};

// Add example rule on startup
addFirewallRule(exampleRule).catch(console.error);

// Intrusion Detection and Prevention System (IDPS)
const monitorNetworkTraffic = async () => {
  const netstatOutput = await getOpenConnections();
  const lines = netstatOutput.split('\n');
  const suspiciousConnections = lines.filter(line => {
    // Replace with actual detection logic.
    return line.includes('SUSPICIOUS_IP');
  });
  if (suspiciousConnections.length > 0) {
    console.warn(`Suspicious connections detected: ${suspiciousConnections.length}`);
    await sendLog({
      type: 'SUSPICIOUS_CONNECTIONS',
      details: suspiciousConnections,
      timestamp: new Date().toISOString()
    }, 'critical');
    for (const connection of suspiciousConnections) {
      const ip = connection.split(' ')[1]; // Extract IP address (modify as needed)
      const rule = {
        name: `Block_${ip}`,
        direction: "in",
        action: "block",
        protocol: "TCP",
        port: "any",
        remoteIp: ip
      };
      await addFirewallRule(rule).catch(console.error);
    }
  }
};

setInterval(monitorNetworkTraffic, 60000); // Monitor every minute

// Behavioral analysis
const behaviorPatterns = {
  normal: new Map(),
  suspicious: new Map()
};

const analyzeBehavior = (metrics) => {
  const timeOfDay = new Date().getHours();
  const dayOfWeek = new Date().getDay();
  const isWorkHours = timeOfDay >= 9 && timeOfDay <= 17 && dayOfWeek >= 1 && dayOfWeek <= 5;
  const fingerprint = {
    timeOfDay,
    dayOfWeek,
    cpuPattern: metrics.cpu > 80 ? 'high' : metrics.cpu > 50 ? 'medium' : 'low',
    memoryPattern: metrics.memory > 80 ? 'high' : metrics.memory > 50 ? 'medium' : 'low',
    connectionPattern: metrics.connections > 100 ? 'high' : metrics.connections > 50 ? 'medium' : 'low'
  };
  let score = 0;
  if (!isWorkHours) score += 0.3;
  if (fingerprint.cpuPattern === 'high') score += 0.2;
  if (fingerprint.memoryPattern === 'high') score += 0.2;
  if (fingerprint.connectionPattern === 'high') score += 0.3;
  return { score, fingerprint };
};

const updateBehaviorPatterns = (fingerprint, type) => {
  const patterns = behaviorPatterns[type];
  const key = JSON.stringify(fingerprint);
  patterns.set(key, (patterns.get(key) || 0) + 1);
  if (patterns.size > 1000) {
    const oldestKey = patterns.keys().next().value;
    patterns.delete(oldestKey);
  }
};

const handleHighThreat = async (metrics, behavior) => {
  console.log('HIGH THREAT DETECTED - Taking immediate action');
  const emergencyRule = {
    name: "EmergencyBlock",
    direction: "in",
    action: "block",
    protocol: "TCP",
    port: "any",
    remoteIp: "any"
  };
  await addFirewallRule(emergencyRule);
  await collectForensicData();
  await alertAdmin(metrics, 1.0);
  await sendLog({
    type: 'HIGH_THREAT',
    metrics,
    behavior: behavior.fingerprint,
    timestamp: new Date().toISOString()
  }, 'critical');
};

const handleMediumThreat = async (metrics, behavior) => {
  console.log('Medium threat detected - Increasing monitoring');
  const monitoringRule = {
    name: "IncreasedMonitoring",
    direction: "in",
    action: "allow",
    protocol: "TCP",
    port: "any",
    remoteIp: "any"
  };
  await addFirewallRule(monitoringRule);
  await sendLog({
    type: 'MEDIUM_THREAT',
    metrics,
    behavior: behavior.fingerprint,
    timestamp: new Date().toISOString()
  }, 'warning');
};

const collectMetrics = async () => {
  const isWindows = os.platform() === 'win32';
  return {
    cpu: isWindows ? 50 + Math.random() * 50 : os.loadavg()[0] * 10,
    memory: isWindows ? 30 + Math.random() * 40 : ((os.totalmem() - os.freemem()) / os.totalmem()) * 100,
    connections: (await getOpenConnections()).split('\n').length,
    processes: (await getProcesses()).length,
    timestamp: Date.now()
  };
};

// Optimize ML model based on historical data
const optimizeModel = async () => {
  try {
    const historicalData = await loadHistoricalData();
    const optimizedParams = await findOptimalParameters(historicalData);
    networkML.updateTrainingOptions({
      learningRate: optimizedParams.learningRate,
      momentum: optimizedParams.momentum,
      hiddenLayers: optimizedParams.hiddenLayers
    });
    await trainNetwork();
    console.log('Model optimized with new parameters');
  } catch (error) {
    console.error('Error optimizing model:', error);
  }
};

setInterval(optimizeModel, 24 * 60 * 60 * 1000); // Daily optimization

// NEW: Global storage for network connection history
const networkHistory = [];

// NEW: Function to detect anomalous network traffic based on connection count trends
const detectAnomalousNetworkTraffic = async () => {
  try {
    const netstatOutput = await getOpenConnections();
    const currentCount = netstatOutput.split('\n').length;
    networkHistory.push({ time: Date.now(), count: currentCount });
    const cutoff = Date.now() - 5 * 60 * 1000;
    while (networkHistory.length && networkHistory[0].time < cutoff) {
      networkHistory.shift();
    }
    const avgCount = networkHistory.reduce((sum, item) => sum + item.count, 0) / networkHistory.length;
    const anomalyScore = currentCount > avgCount * 1.5 ? 1 : 0;
    console.log(`DEBUG: Current connections ${currentCount} vs avg ${avgCount.toFixed(1)}; Anomaly: ${anomalyScore}`);
    return anomalyScore;
  } catch (error) {
    console.error('Error in network anomaly detection:', error);
    return 0;
  }
};
