#!/usr/bin/env node

process.title = 'edumeet-server';
require('dotenv').config()


const config = require('./config/config');
const fs = require('fs');
const http = require('http');
const spdy = require('spdy');
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const mediasoup = require('mediasoup');
const AwaitQueue = require('awaitqueue');
const Logger = require('./lib/Logger');
const Room = require('./lib/Room');
const Peer = require('./lib/Peer');
const base64 = require('base-64');
const helmet = require('helmet');
const userRoles = require('./userRoles');
const {
	loginHelper,
	logoutHelper
} = require('./httpHelper');
// auth
const passport = require('passport');
const LTIStrategy = require('passport-lti');
const imsLti = require('ims-lti');
const SAMLStrategy = require('passport-saml').Strategy;
const LocalStrategy = require('passport-local').Strategy;
const redis = require('redis');
const redisClient = redis.createClient(config.redisOptions);
const { Issuer, Strategy } = require('openid-client');
const expressSession = require('express-session');
const RedisStore = require('connect-redis')(expressSession);
const sharedSession = require('express-socket.io-session');
const interactiveServer = require('./lib/interactiveServer');
const promExporter = require('./lib/promExporter');
const { v4: uuidv4 } = require('uuid');
var cors = require('cors')
const BasicStrategy = require('passport-http').BasicStrategy;
const jwt = require('jsonwebtoken');

/* eslint-disable no-console */
console.log('- process.env.DEBUG:', process.env.DEBUG);
console.log('- config.mediasoup.worker.logLevel:', config.mediasoup.worker.logLevel);
console.log('- config.mediasoup.worker.logTags:', config.mediasoup.worker.logTags);
/* eslint-enable no-console */

const logger = new Logger();

const queue = new AwaitQueue();

let statusLogger = null;

if ('StatusLogger' in config)
	statusLogger = new config.StatusLogger();

// mediasoup Workers.
// @type {Array<mediasoup.Worker>}
const mediasoupWorkers = [];

// Map of Room instances indexed by roomId.
const rooms = new Map();

// Map of Peer instances indexed by peerId.
const peers = new Map();

// TLS server configuration.
const tls =
{
	cert          : fs.readFileSync(config.tls.cert),
	key           : fs.readFileSync(config.tls.key),
	secureOptions : 'tlsv12',
	ciphers       :
		[
			'ECDHE-ECDSA-AES128-GCM-SHA256',
			'ECDHE-RSA-AES128-GCM-SHA256',
			'ECDHE-ECDSA-AES256-GCM-SHA384',
			'ECDHE-RSA-AES256-GCM-SHA384',
			'ECDHE-ECDSA-CHACHA20-POLY1305',
			'ECDHE-RSA-CHACHA20-POLY1305',
			'DHE-RSA-AES128-GCM-SHA256',
			'DHE-RSA-AES256-GCM-SHA384'
		].join(':'),
	honorCipherOrder : true
};

const app = express();

const whitelist = [
	'http://localhost'
];

const whitelistEnv = process.env.WHITELIST_FRONT_URLS;

if (whitelistEnv) {
  const whitelistValues = whitelistEnv.split(',');

  whitelistValues.forEach(value => {
    if (value.trim() !== '') {
      whitelist.push(value.trim());
    }
  });
}

console.log("Whitelisted URL: ", whitelist);

var corsOptions = {
  origin: function (origin, callback) {
		console.log('%cserver.js line:93 Cors check origin', 'color: #007acc;', origin);
    if (whitelist.indexOf(origin) !== -1) {
      callback(null, true)
    } else {
      callback(null, true)
    }
	},
	credentials: true
}

app.use(cors(corsOptions))
// app.use(cors())
app.use(helmet.hsts());
const sharedCookieParser=cookieParser();

app.use(sharedCookieParser);
app.use(bodyParser.json({ limit: '5mb' }));
app.use(bodyParser.urlencoded({ limit: '5mb', extended: true }));

const session = expressSession({
	secret            : config.cookieSecret,
	name              : config.cookieName,
	resave            : true,
	saveUninitialized : true,
	store             : new RedisStore({ client: redisClient }),
	cookie            : {
		secure   : true,
		httpOnly : true,
		maxAge   : 60 * 60 * 1000 // Expire after 1 hour since last request from user
	}
});

if (config.trustProxy)
{
	app.set('trust proxy', config.trustProxy);
}

app.use(session);

passport.serializeUser((user, done) =>
{
	done(null, user);
});

passport.deserializeUser((user, done) =>
{
	done(null, user);
});

let mainListener;
let io;
let oidcClient;
let oidcStrategy;
let samlStrategy;
let localStrategy;

async function run()
{
	try
	{
		// Open the interactive server.
		await interactiveServer(rooms, peers);

		// start Prometheus exporter
		if (config.prometheus)
		{
			await promExporter(rooms, peers, config.prometheus);
		}

		if (typeof (config.auth) === 'undefined')
		{
			logger.warn('Auth is not configured properly!');
		}
		else
		{
			await setupAuth();
		}

		// Run a mediasoup Worker.
		await runMediasoupWorkers();

		// Run HTTPS server.
		await runHttpsServer();

		// Run WebSocketServer.
		await runWebSocketServer();

		// eslint-disable-next-line no-unused-vars
		const errorHandler = (err, req, res, next) =>
		{
			const trackingId = uuidv4();
			console.log('Error ', err)
			res.status(500).send(
				`<h1>Internal Server Error</h1>
				<p>If you report this error, please also report this 
				<i>tracking ID</i> which makes it possible to locate your session
				in the logs which are available to the system administrator: 
				<b>${trackingId}</b></p>`
			);
			logger.error(
				'Express error handler dump with tracking ID: %s, error dump: %o',
				trackingId, err);
		};

		// eslint-disable-next-line no-unused-vars
		app.use(errorHandler);
	}
	catch (error)
	{
		logger.error('run() [error:"%o"]', error);
	}
}

function statusLog()
{
	if (statusLogger)
	{
		statusLogger.log({
			rooms : rooms,
			peers : peers
		});
	}
}




async function setupAuth()
{

	passport.use(new BasicStrategy(
		function(username, password, done) {
			if(username === config.auth.username && password === config.auth.secret){
				return done(null, {username});
			}else{
				return done(null, false); 
			}
		}
	));

	app.use(passport.initialize());
	app.use(passport.session());

}

async function runHttpsServer()
{
	app.use(compression());

	app.use('/.well-known/acme-challenge', express.static('public/.well-known/acme-challenge'));

	
	app.post('/session',
	passport.authenticate('basic', { session: false }),
	function(req, res) {
    
		const token = jwt.sign({ peerId: req.body.peerId, roomId: req.body.roomId}, config.jwtSecret);
		console.log('Created token for ', req.body.peerId)
		res.json({token})
	
  });

	app.get('/rooms-count', 
	passport.authenticate('basic', { session: false }),
	function(req, res) {
		console.log('GET rooms ', rooms)
		return res.json({count: rooms.size})
	})

	

	if (config.httpOnly === true)
	{
		// http
		mainListener = http.createServer(app);
	}
	else
	{
		// https
		mainListener = spdy.createServer(tls, app);

		// http
		const redirectListener = http.createServer(app);

		if (config.listeningHost)
			redirectListener.listen(config.listeningRedirectPort, config.listeningHost);
		else
			redirectListener.listen(config.listeningRedirectPort);
	}

	// https or http
	if (config.listeningHost)
		mainListener.listen(config.listeningPort, config.listeningHost);
	else
		mainListener.listen(config.listeningPort);
}


/**
 * Create a WebSocketServer to allow WebSocket connections from browsers.
 */
async function runWebSocketServer()
{
	io = require('socket.io')(mainListener, { cookie: false, cors: corsOptions });
	// io = require('socket.io')(mainListener, { cookie: false,  });

	io.use(
		sharedSession(session, sharedCookieParser, { autoSave: true })
	);

	// Handle connections from clients.
	io.on('connection', (socket) =>
	{
	
		
		const authToken = socket.handshake.query.token;
		if(!authToken){
			socket.disconnect(true);
			return;
		}

		let decoded;
		let roomId;
		let peerId

		try {
			
			decoded = jwt.verify(authToken, config.jwtSecret);
			roomId = decoded.roomId
			peerId = decoded.peerId

		} catch (error) {
			
			console.log('Disconnect due to:', error);
			socket.disconnect(true);
			return;
		}


		
		const { token } = socket.handshake.query;
		if (!token) {
			console.log("No token");
		} else {
			console.log("token", token);
		}

		if (!roomId || !peerId)
		{
			logger.warn('connection request without roomId and/or peerId');

			socket.disconnect(true);

			return;
		}

		logger.info(
			'connection request [roomId:"%s", peerId:"%s"]', roomId, peerId);

		queue.push(async () =>
		{
			const { token } = socket.handshake.session;

			const room = await getOrCreateRoom({ roomId });

			// if(roomId.startsWith('test')&& room._allPeers.size>0){
			// 	socket.disconnect(true);
			// 	return;
			// }

			let peer = peers.get(peerId);
			let returning = false;

			if (peer && !token)
			{ // Don't allow hijacking sessions
				socket.disconnect(true);

				return;
			}
			else if (token && room.verifyPeer({ id: peerId, token }))
			{ // Returning user, remove if old peer exists
				if (peer)
					peer.close();

				returning = true;
			}

			peer = new Peer({ id: peerId, roomId, socket });

			peers.set(peerId, peer);

			peer.on('close', () =>
			{
				peers.delete(peerId);

				statusLog();
			});

			if (
				Boolean(socket.handshake.session.passport) &&
				Boolean(socket.handshake.session.passport.user)
			)
			{
				const {
					id,
					displayName,
					picture,
					email,
					_userinfo
				} = socket.handshake.session.passport.user;

				peer.authId = id;
				peer.displayName = displayName;
				peer.picture = picture;
				peer.email = email;
				peer.authenticated = true;

				if (typeof config.userMapping === 'function')
				{
					await config.userMapping({ peer, room, roomId, userinfo: _userinfo });
				}
			}

			room.handlePeer({ peer, returning });

			statusLog();
		})
			.catch((error) =>
			{
				logger.error('room creation or room joining failed [error:"%o"]', error);

				if (socket)
					socket.disconnect(true);

				return;
			});
	});
}

/**
 * Launch as many mediasoup Workers as given in the configuration file.
 */
async function runMediasoupWorkers()
{
	const { numWorkers } = config.mediasoup;

	logger.info('running %d mediasoup Workers...', numWorkers);

	for (let i = 0; i < numWorkers; ++i)
	{
		const worker = await mediasoup.createWorker(
			{
				logLevel   : config.mediasoup.worker.logLevel,
				logTags    : config.mediasoup.worker.logTags,
				rtcMinPort : config.mediasoup.worker.rtcMinPort,
				rtcMaxPort : config.mediasoup.worker.rtcMaxPort
			});

		worker.on('died', () =>
		{
			logger.error(
				'mediasoup Worker died, exiting  in 2 seconds... [pid:%d]', worker.pid);

			setTimeout(() => process.exit(1), 2000);
		});

		mediasoupWorkers.push(worker);
	}
}

/**
 * Get a Room instance (or create one if it does not exist).
 */
async function getOrCreateRoom({ roomId })
{
	console.log("roomId", roomId);
	let room = rooms.get(roomId);


	// If the Room does not exist create a new one.
	if (!room)
	{
		console.log('creating a new Room [roomId:"%s"]', roomId);

		// const mediasoupWorker = getMediasoupWorker();

		room = await Room.create({ mediasoupWorkers, roomId, peers });

		console.log('room', room);

		rooms.set(roomId, room);

		statusLog();

		room.on('close', () =>
		{
			rooms.delete(roomId);

			statusLog();
		});
	}

	return room;
}

run();
