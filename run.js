const { Ed25519Keypair } = require('@mysten/sui.js/keypairs/ed25519');
const { getFullnodeUrl, SuiClient } = require('@mysten/sui.js/client');
const { TransactionBlock } = require('@mysten/sui.js/transactions');
const { decodeSuiPrivateKey } = require('@mysten/sui.js/cryptography');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const readline = require('readline');
const { HttpsProxyAgent } = require('https-proxy-agent');

require('dotenv').config();

const PACKAGE_ID = '0x4cb081457b1e098d566a277f605ba48410e26e66eaab5b3be4f6c560e9501800';
const SUI_RPC_URL = process.env.SUI_RPC_URL || getFullnodeUrl('testnet');
const DEFAULT_IMAGE_URL = 'https://picsum.photos/800/600';
const LOCAL_IMAGE_PATH = path.join(__dirname, 'image.jpg');
const PUBLISHER_URLS = [
  'https://seal-example.vercel.app/publisher1/v1/blobs',
  'https://seal-example.vercel.app/publisher2/v1/blobs',
  'https://seal-example.vercel.app/publisher3/v1/blobs',
  'https://seal-example.vercel.app/publisher4/v1/blobs',
  'https://seal-example.vercel.app/publisher5/v1/blobs',
  'https://seal-example.vercel.app/publisher6/v1/blobs',
];

const SYMBOLS = {
  info: '📌',
  success: '✅',
  error: '❌',
  warning: '⚠️',
  processing: '🔄',
  wallet: '👛',
  upload: '📤',
  download: '📥',
  network: '🌐',
  divider: '═════════════════════════════════════════'
};

const logger = {
  info: (message) => console.log(`${SYMBOLS.info} ${message}`),
  success: (message) => console.log(`${SYMBOLS.success} ${message}`),
  error: (message) => console.log(`${SYMBOLS.error} ${message}`),
  warning: (message) => console.log(`${SYMBOLS.warning} ${message}`),
  processing: (message) => console.log(`${SYMBOLS.processing} ${message}`),
  wallet: (message) => console.log(`${SYMBOLS.wallet} ${message}`),
  upload: (message) => console.log(`${SYMBOLS.upload} ${message}`),
  download: (message) => console.log(`${SYMBOLS.download} ${message}`),
  network: (message) => console.log(`${SYMBOLS.network} ${message}`),
  divider: () => console.log(SYMBOLS.divider),
  result: (key, value) => console.log(`   ${key.padEnd(15)}: ${value}`)
};

class ProxyManager {
  constructor(proxyFilePath) {
    this.proxyFilePath = proxyFilePath;
    this.proxies = [];
    this.currentProxyIndex = 0;
    this.loadProxies();
  }

  loadProxies() {
    try {
      if (fs.existsSync(this.proxyFilePath)) {
        const proxyData = fs.readFileSync(this.proxyFilePath, 'utf8');
        this.proxies = proxyData
          .split('\n')
          .map(proxy => proxy.trim())
          .filter(proxy => proxy && !proxy.startsWith('#'));

        if (this.proxies.length > 0) {
          logger.success(`Loaded ${this.proxies.length} proxies from ${this.proxyFilePath}`);
        } else {
          logger.warning('No proxies found in the proxy file. Will proceed without proxies.');
        }
      } else {
        logger.warning(`Proxy file ${this.proxyFilePath} not found. Will proceed without proxies.`);
      }
    } catch (error) {
      logger.error(`Error loading proxies: ${error.message}`);
    }
  }

  getNextProxy() {
    if (this.proxies.length === 0) return null;

    const proxy = this.proxies[this.currentProxyIndex];
    this.currentProxyIndex = (this.currentProxyIndex + 1) % this.proxies.length;
    return this.formatProxy(proxy);
  }

  formatProxy(proxyString) {
    if (!proxyString) return null;

    if (proxyString.includes('@')) {
      const [auth, hostPort] = proxyString.split('@');
      const [username, password] = auth.split(':');
      const [host, port] = hostPort.split(':');
      return {
        host,
        port,
        auth: { username, password }
      };
    }

    if (proxyString.split(':').length === 4) {
      const [host, port, username, password] = proxyString.split(':');
      return {
        host,
        port,
        auth: { username, password }
      };
    }

    if (proxyString.split(':').length === 2) {
      const [host, port] = proxyString.split(':');
      return { host, port };
    }

    return null;
  }

  createProxyAgent() {
    const proxy = this.getNextProxy();
    if (!proxy) return null;

    let proxyUrl = `http://${proxy.host}:${proxy.port}`;

    if (proxy.auth && proxy.auth.username && proxy.auth.password) {
      proxyUrl = `http://${proxy.auth.username}:${proxy.auth.password}@${proxy.host}:${proxy.port}`;
    }

    logger.network(`Using proxy: ${proxy.host}:${proxy.port}`);
    return new HttpsProxyAgent(proxyUrl);
  }
}

class SuiAllowlistBot {
  constructor(keyInput, proxyManager = null) {
    this.client = new SuiClient({ url: SUI_RPC_URL });
    this.proxyManager = proxyManager;
    this.address = this.initializeKeypair(keyInput);
  }

  initializeKeypair(keyInput) {
    try {
      if (keyInput.startsWith('suiprivkey')) {
        const { secretKey } = decodeSuiPrivateKey(keyInput);
        this.keypair = Ed25519Keypair.fromSecretKey(secretKey);
      } else if (keyInput.startsWith('0x') || /^[0-9a-fA-F]{64}$/.test(keyInput)) {
        const privateKeyBytes = Buffer.from(keyInput.startsWith('0x') ? keyInput.slice(2) : keyInput, 'hex');
        this.keypair = Ed25519Keypair.fromSecretKey(privateKeyBytes);
      } else if (/^[A-Za-z0-9+/=]+$/.test(keyInput) && keyInput.length === 44) {
        const privateKeyBytes = Buffer.from(keyInput, 'base64');
        this.keypair = Ed25519Keypair.fromSecretKey(privateKeyBytes);
      } else {
        this.keypair = Ed25519Keypair.deriveKeypair(keyInput);
      }

      const address = this.keypair.getPublicKey().toSuiAddress();
      logger.info(`Initialized wallet with address: ${address}`);
      return address;
    } catch (error) {
      logger.error(`Error initializing keypair: ${error.message}`);
      throw error;
    }
  }

  getAddress() {
    return this.address;
  }

  generateRandomName() {
    const adjectives = ['cool', 'awesome', 'amazing', 'brilliant', 'excellent'];
    const nouns = ['project', 'creation', 'work', 'masterpiece', 'innovation'];
    const randomAdjective = adjectives[Math.floor(Math.random() * adjectives.length)];
    const randomNoun = nouns[Math.floor(Math.random() * nouns.length)];
    const randomNum = Math.floor(Math.random() * 1000);
    return `${randomAdjective}-${randomNoun}-${randomNum}`;
  }

  async createAllowlist(name = null) {
    const entryName = name || this.generateRandomName();
    logger.processing(`Creating allowlist with name: ${entryName}`);
    const txb = new TransactionBlock();
    txb.moveCall({
      target: `${PACKAGE_ID}::allowlist::create_allowlist_entry`,
      arguments: [txb.pure(entryName)],
    });
    txb.setGasBudget(10000000);

    try {
      const result = await this.client.signAndExecuteTransactionBlock({
        transactionBlock: txb,
        signer: this.keypair,
        options: { showEffects: true, showEvents: true },
        requestType: 'WaitForLocalExecution',
      });
      const createdObjects = result.effects?.created || [];
      const entryObjectId = createdObjects.find(obj => obj.owner?.AddressOwner === this.getAddress())?.reference?.objectId;
      const allowlistId = createdObjects.find(obj => obj.owner?.Shared)?.reference?.objectId;

      if (!allowlistId || !entryObjectId) {
        throw new Error('Failed to retrieve allowlistId or entryObjectId');
      }

      logger.success(`Allowlist created successfully`);
      logger.result('Allowlist ID', allowlistId);
      logger.result('Entry ID', entryObjectId);
      return { allowlistId, entryObjectId };
    } catch (error) {
      logger.error(`Error creating allowlist: ${error.message}`);
      throw error;
    }
  }

  async addToAllowlist(allowlistId, entryObjectId, address) {
    logger.processing(`Adding ${address} to allowlist`);
    const txb = new TransactionBlock();
    txb.moveCall({
      target: `${PACKAGE_ID}::allowlist::add`,
      arguments: [
        txb.object(allowlistId),
        txb.object(entryObjectId),
        txb.pure(address),
      ],
    });
    txb.setGasBudget(10000000);

    try {
      const result = await this.client.signAndExecuteTransactionBlock({
        transactionBlock: txb,
        signer: this.keypair,
        options: { showEffects: true },
        requestType: 'WaitForLocalExecution',
      });
      logger.success(`Address added to allowlist successfully`);
      return result;
    } catch (error) {
      logger.error(`Error adding to allowlist: ${error.message}`);
      throw error;
    }
  }

  async addServiceEntry(amount, duration, name = null) {
    const serviceName = name || this.generateRandomName();
    logger.processing(`Adding service entry: ${serviceName} (Amount: ${amount}, Duration: ${duration})`);
    const txb = new TransactionBlock();
    txb.moveCall({
      target: `${PACKAGE_ID}::subscription::create_service_entry`,
      arguments: [
        txb.pure(amount, 'u64'),
        txb.pure(duration, 'u64'),
        txb.pure(serviceName),
      ],
    });
    txb.setGasBudget(10000000);

    try {
      const result = await this.client.signAndExecuteTransactionBlock({
        transactionBlock: txb,
        signer: this.keypair,
        options: { showEffects: true },
        requestType: 'WaitForLocalExecution',
      });
      const createdObjects = result.effects?.created || [];
      const serviceEntryId = createdObjects.find(obj => obj.owner?.AddressOwner === this.getAddress())?.reference?.objectId;
      const sharedObjectId = createdObjects.find(obj => obj.owner?.Shared)?.reference?.objectId;

      if (!serviceEntryId || !sharedObjectId) {
        throw new Error('Failed to retrieve serviceEntryId or sharedObjectId');
      }

      logger.success(`Service entry created successfully`);
      logger.result('Shared ID', sharedObjectId);
      logger.result('Entry ID', serviceEntryId);
      return { sharedObjectId, serviceEntryId };
    } catch (error) {
      logger.error(`Error adding service entry: ${error.message}`);
      throw error;
    }
  }

  async fetchImageFromUrl(imageUrl) {
    logger.download(`Fetching image from URL`);

    const axiosConfig = {};
    if (this.proxyManager) {
      const proxyAgent = this.proxyManager.createProxyAgent();
      if (proxyAgent) {
        axiosConfig.httpsAgent = proxyAgent;
      }
    }

    try {
      const response = await axios({
        method: 'get',
        url: imageUrl,
        responseType: 'arraybuffer',
        ...axiosConfig
      });
      const imageData = Buffer.from(response.data);
      logger.success(`Image fetched: ${(imageData.length / 1024).toFixed(2)} KB`);
      return imageData;
    } catch (error) {
      logger.error(`Error fetching image: ${error.message}`);
      throw error;
    }
  }

  async loadLocalImage(imagePath) {
    logger.download(`Loading local image`);
    try {
      const imageData = fs.readFileSync(imagePath);
      logger.success(`Image loaded: ${(imageData.length / 1024).toFixed(2)} KB`);
      return imageData;
    } catch (error) {
      logger.error(`Error loading local image: ${error.message}`);
      throw error;
    }
  }

  async uploadBlob(imageSource, epochs = 1, maxRetries = 15) {
    let imageData;
    if (typeof imageSource === 'string' && imageSource.match(/^https?:\/\//)) {
      imageData = await this.fetchImageFromUrl(imageSource);
    } else if (typeof imageSource === 'string' && imageSource === LOCAL_IMAGE_PATH) {
      imageData = await this.loadLocalImage(imageSource);
    } else {
      imageData = imageSource;
    }

    logger.upload(`Uploading blob for ${epochs} epochs`);
    let attempt = 1;
    const delayMs = 5000;

    while (attempt <= maxRetries) {
      const randomIndex = Math.floor(Math.random() * PUBLISHER_URLS.length);
      const publisherUrl = `${PUBLISHER_URLS[randomIndex]}?epochs=${epochs}`;
      logger.processing(`Attempt ${attempt}: Using publisher${randomIndex + 1}`);

      try {
        const axiosConfig = {};
        if (this.proxyManager) {
          const proxyAgent = this.proxyManager.createProxyAgent();
          if (proxyAgent) {
            axiosConfig.httpsAgent = proxyAgent;
          }
        }

        const response = await axios({
          method: 'put',
          url: publisherUrl,
          headers: { 'Content-Type': 'application/octet-stream' },
          data: imageData,
          ...axiosConfig
        });

        let blobId;
        if (response.data && response.data.newlyCreated && response.data.newlyCreated.blobObject) {
          blobId = response.data.newlyCreated.blobObject.blobId;
          console.log('newlyCreated');
        } else if (response.data && response.data.alreadyCertified) {
          blobId = response.data.alreadyCertified.blobId;
          console.log('alreadyCertified');
        } else {
          throw new Error(`Invalid response structure from publisher`);
        }

        if (!blobId) {
          throw new Error(`Blob ID is missing in response`);
        }

        logger.success(`Blob uploaded successfully`);
        logger.result('Blob ID', blobId);
        return blobId;
      } catch (error) {
        logger.error(`Upload failed on attempt ${attempt}: ${error.message}`);
        if (attempt === maxRetries) {
          logger.error(`Max retries (${maxRetries}) reached. Giving up.`);
          throw new Error('Failed to upload blob after maximum retries');
        }
        logger.warning(`Retrying in ${delayMs / 1000} seconds...`);
        await new Promise(resolve => setTimeout(resolve, delayMs));
        attempt++;
      }
    }
  }

  async publishToAllowlist(allowlistId, entryObjectId, blobId) {
    logger.processing(`Publishing blob to allowlist`);
    const txb = new TransactionBlock();
    txb.moveCall({
      target: `${PACKAGE_ID}::allowlist::publish`,
      arguments: [
        txb.object(allowlistId),
        txb.object(entryObjectId),
        txb.pure(blobId),
      ],
    });
    txb.setGasBudget(10000000);

    try {
      await this.client.signAndExecuteTransactionBlock({
        transactionBlock: txb,
        signer: this.keypair,
        options: { showEffects: true },
        requestType: 'WaitForLocalExecution',
      });
      logger.success(`Content published to allowlist successfully`);
      return true;
    } catch (error) {
      logger.error(`Error publishing to allowlist: ${error.message}`);
      throw error;
    }
  }

  async publishToSubscription(sharedObjectId, serviceEntryId, blobId) {
    logger.processing(`Publishing blob to subscription service`);
    const txb = new TransactionBlock();
    txb.moveCall({
      target: `${PACKAGE_ID}::subscription::publish`,
      arguments: [
        txb.object(sharedObjectId),
        txb.object(serviceEntryId),
        txb.pure(blobId),
      ],
    });
    txb.setGasBudget(10000000);

    try {
      await this.client.signAndExecuteTransactionBlock({
        transactionBlock: txb,
        signer: this.keypair,
        options: { showEffects: true },
        requestType: 'WaitForLocalExecution',
      });
      logger.success(`Content published to subscription successfully`);
      return true;
    } catch (error) {
      logger.error(`Error publishing to subscription: ${error.message}`);
      throw error;
    }
  }

  async runAllowlistWorkflow(imageSource = DEFAULT_IMAGE_URL, additionalAddresses = [], count = 1) {
    logger.info(`Starting allowlist workflow for ${count} allowlist(s)`);
    const results = [];

    try {
      for (let i = 1; i <= count; i++) {
        logger.divider();
        logger.info(`Processing allowlist ${i} of ${count}`);

        const { allowlistId, entryObjectId } = await this.createAllowlist();
        await this.addToAllowlist(allowlistId, entryObjectId, this.getAddress());

        if (additionalAddresses.length > 0) {
          for (const address of additionalAddresses) {
            await this.addToAllowlist(allowlistId, entryObjectId, address);
          }
        }

        const blobId = await this.uploadBlob(imageSource);
        await this.publishToAllowlist(allowlistId, entryObjectId, blobId);

        results.push({ allowlistId, entryObjectId, blobId });
      }

      logger.divider();
      logger.success(`Allowlist workflow completed successfully`);
      return results;
    } catch (error) {
      logger.error(`Allowlist workflow failed: ${error.message}`);
      throw error;
    }
  }

  async runServiceSubscriptionWorkflow(imageSource = DEFAULT_IMAGE_URL, count = 1) {
    logger.info(`Starting service subscription workflow for ${count} service(s)`);
    const results = [];

    try {
      for (let i = 1; i <= count; i++) {
        logger.divider();
        logger.info(`Processing service ${i} of ${count}`);

        const { sharedObjectId, serviceEntryId } = await this.addServiceEntry(10, 60000000);
        const blobId = await this.uploadBlob(imageSource);
        await this.publishToSubscription(sharedObjectId, serviceEntryId, blobId);

        results.push({ sharedObjectId, serviceEntryId, blobId });
      }

      logger.divider();
      logger.success(`Service subscription workflow completed successfully`);
      return results;
    } catch (error) {
      logger.error(`Service subscription workflow failed: ${error.message}`);
      throw error;
    }
  }
}

class WalletManager {
  constructor(walletFilePath) {
    this.walletFilePath = walletFilePath;
    this.wallets = [];
    this.loadWallets();
  }

  loadWallets() {
    try {
      if (fs.existsSync(this.walletFilePath)) {
        const walletData = fs.readFileSync(this.walletFilePath, 'utf8');
        this.wallets = walletData
          .split('\n')
          .map(phrase => phrase.trim())
          .filter(phrase => phrase && !phrase.startsWith('#'));

        logger.success(`Loaded ${this.wallets.length} wallet(s) from ${this.walletFilePath}`);
      } else {
        logger.warning(`Wallet file ${this.walletFilePath} not found.`);
        this.wallets = [];
      }
    } catch (error) {
      logger.error(`Error loading wallets: ${error.message}`);
      this.wallets = [];
    }
  }

  getWallets() {
    return this.wallets;
  }

  hasWallets() {
    return this.wallets.length > 0;
  }
}

async function promptUser(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  try {
    return new Promise((resolve) => {
      rl.question(question, (answer) => {
        rl.close();
        resolve(answer.trim());
      });
    });
  } catch (error) {
    rl.close();
    return '';
  }
}

async function main() {
  console.log('\n(BETA)SUI SEAL AUTO BOT - AIRDROP INSIDERS');
  logger.divider();

  const walletPath = path.join(__dirname, 'wallets.txt');
  const proxyPath = path.join(__dirname, 'proxies.txt');
  const pkPath = path.join(__dirname, 'pk.txt');

  const proxyManager = new ProxyManager(proxyPath);

  const walletManager = new WalletManager(walletPath);

  let wallets = [];

  if (walletManager.hasWallets()) {
    const useMultipleWallets = await promptUser('\nMultiple wallets detected. Use them? (y/n): ');
    if (useMultipleWallets.toLowerCase() === 'y') {
      wallets = walletManager.getWallets();
      logger.info(`Using ${wallets.length} wallets from wallets.txt`);
    }
  }

  if (wallets.length === 0) {
    if (!fs.existsSync(pkPath)) {
      logger.error('No wallet found. Please create pk.txt with your passphrase or wallets.txt for multiple wallets.');
      process.exit(1);
    }
    const passphrase = fs.readFileSync(pkPath, 'utf8').trim();
    wallets = [passphrase];
    logger.info('Using single wallet from pk.txt');
  }

  logger.divider();
  console.log('Choose action:');
  console.log('1. Create Allowlist and Publish Blob');
  console.log('2. Create Service Subscription and Upload Blob');
  const choice = await promptUser('Enter choice (1 or 2): ');

  try {
    let imageSource;
    logger.divider();
    console.log('Image source options:');
    console.log('1. Use URL (default: https://picsum.photos/800/600)');
    console.log('2. Use local file (image.jpg in script directory)');
    const imageChoice = await promptUser('Choose image source (1 or 2): ');

    if (imageChoice === '2') {
      if (!fs.existsSync(LOCAL_IMAGE_PATH)) {
        logger.error('Error: image.jpg not found in script directory.');
        process.exit(1);
      }
      imageSource = LOCAL_IMAGE_PATH;
      logger.info('Using local image.jpg');
    } else {
      imageSource = await promptUser('Enter image URL (or press Enter for default): ') || DEFAULT_IMAGE_URL;
      logger.info(`Using image URL: ${imageSource}`);
    }

    const countInput = await promptUser('Enter number of tasks per wallet (default 1): ');
    const count = parseInt(countInput || '1', 10);
    if (isNaN(count) || count < 1) {
      logger.warning('Invalid number. Using default value of 1.');
      count = 1;
    }

    let additionalAddresses = [];
    if (choice === '1') {
      const addressesInput = await promptUser('Enter additional addresses to add to allowlist (comma-separated, or press Enter for none): ');
      if (addressesInput.trim()) {
        additionalAddresses = addressesInput
          .split(',')
          .map(addr => addr.trim())
          .filter(addr => addr);
        logger.info(`Will add ${additionalAddresses.length} additional addresses to each allowlist`);
      }
    }

    for (let i = 0; i < wallets.length; i++) {
      logger.divider();
      logger.wallet(`Processing wallet ${i+1} of ${wallets.length}`);

      const bot = new SuiAllowlistBot(wallets[i], proxyManager);
      logger.wallet(`Wallet address: ${bot.getAddress()}`);

      if (choice === '1') {
        logger.info(`Starting allowlist workflow (${count} tasks)`);
        const results = await bot.runAllowlistWorkflow(imageSource, additionalAddresses, count);

        logger.divider();
        logger.success(`Wallet ${i+1} summary:`);
        results.forEach((result, idx) => {
          logger.info(`Allowlist ${idx+1}:`);
          logger.result('Allowlist ID', result.allowlistId);
          logger.result('Entry ID', result.entryObjectId);
          logger.result('Blob ID', result.blobId);
        });
      } else if (choice === '2') {
        logger.info(`Starting service subscription workflow (${count} tasks)`);
        const results = await bot.runServiceSubscriptionWorkflow(imageSource, count);

        logger.divider();
        logger.success(`Wallet ${i+1} summary:`);
        results.forEach((result, idx) => {
          logger.info(`Service ${idx+1}:`);
          logger.result('Shared ID', result.sharedObjectId);
          logger.result('Entry ID', result.serviceEntryId);
          logger.result('Blob ID', result.blobId);
        });
      } else {
        logger.error('Invalid choice. Please enter 1 or 2.');
        break;
      }
    }

    logger.divider();
    logger.success('All tasks completed successfully!');

  } catch (error) {
    logger.error(`Fatal error: ${error.message}`);
  } finally {
    process.exit(0);
  }
}

main();
