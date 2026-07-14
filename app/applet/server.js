import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import https from 'https';
import { URL } from 'url';
import compression from 'compression';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.tailwindcss.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:", "blob:", "https://files.catbox.moe"],
            mediaSrc: ["'self'", "https:", "blob:"],
            connectSrc: ["'self'", "https:", "wss:"],
            fontSrc: ["'self'", "data:", "https:", "https://fonts.gstatic.com"],
            frameSrc: ["'self'", "https://www.youtube.com", "https://player.vimeo.com"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            upgradeInsecureRequests: []
        }
    },
    crossOriginEmbedderPolicy: false
}));

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 1000, 
    message: 'Too many requests from this IP, please try again after 15 minutes'
});

app.use('/api', apiLimiter);


const visitorData = {
    totalVisitors: 0,
    todayVisitors: 0,
    lastReset: new Date().toDateString(),
    regions: {},
    ips: new Map(),
    onlineUsers: 0,
    pageViews: {}
};


const getRegionFromIP = (ip) => {
    ip = ip.split(':').pop() || ip;
    
    if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')) {
        return 'Local Network';
    }
    if (ip.startsWith('41.') || ip.startsWith('197.') || ip.startsWith('154.') || ip.startsWith('196.')) {
        return 'Africa';
    }
    if (ip.startsWith('92.') || ip.startsWith('188.') || ip.startsWith('91.')) {
        return 'Europe';
    }
    if (ip.startsWith('1.') || ip.startsWith('204.')) {
        return 'North America';
    }
    if (ip.startsWith('103.') || ip.startsWith('175.') || ip.startsWith('14.')) {
        return 'Asia';
    }
    if (ip.startsWith('177.') || ip.startsWith('186.') || ip.startsWith('189.')) {
        return 'South America';
    }
    if (ip.startsWith('27.') || ip.startsWith('41.')) {
        return 'Sierra Leone';
    }
    return 'Unknown';
};


const trackVisitor = (ip, page = '/') => {
    const today = new Date().toDateString();
    const cleanIP = ip.split(':').pop() || ip;
    
    if (visitorData.lastReset !== today) {
        visitorData.todayVisitors = 0;
        visitorData.lastReset = today;
    }
    
    const visitorKey = cleanIP + today;
    if (!visitorData.ips.has(visitorKey)) {
        visitorData.totalVisitors++;
        visitorData.todayVisitors++;
        visitorData.ips.set(visitorKey, {
            ip: cleanIP,
            region: getRegionFromIP(cleanIP),
            timestamp: Date.now(),
            pages: [page]
        });
        
        const region = getRegionFromIP(cleanIP);
        visitorData.regions[region] = (visitorData.regions[region] || 0) + 1;
    } else {
        const visitor = visitorData.ips.get(visitorKey);
        if (!visitor.pages.includes(page)) {
            visitor.pages.push(page);
        }
    }
    
    visitorData.pageViews[page] = (visitorData.pageViews[page] || 0) + 1;
    
    
    const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000);
    for (const [key, value] of visitorData.ips) {
        if (value.timestamp < oneDayAgo) {
            visitorData.ips.delete(key);
        }
    }
};


io.on('connection', (socket) => {
    visitorData.onlineUsers++;
    io.emit('visitorUpdate', {
        onlineUsers: visitorData.onlineUsers,
        todayVisitors: visitorData.todayVisitors,
        totalVisitors: visitorData.totalVisitors
    });
    
    socket.on('disconnect', () => {
        visitorData.onlineUsers = Math.max(0, visitorData.onlineUsers - 1);
        io.emit('visitorUpdate', {
            onlineUsers: visitorData.onlineUsers,
            todayVisitors: visitorData.todayVisitors,
            totalVisitors: visitorData.totalVisitors
        });
    });
});


app.use((req, res, next) => {
    const clientIP = req.ip || req.connection?.remoteAddress || '127.0.0.1';
    trackVisitor(clientIP, req.path);
    next();
});


app.use(compression({
    level: 6,
    threshold: 1024,
    filter: (req) => {
        if (req.headers['x-no-compression']) return false;
        return true;
    }
}));


app.use((req, res, next) => {
    if (req.url.startsWith('/assets/') || req.path === '/index.html') {
        return next();
    }
    if (/\.(ts|tsx|map)$/.test(req.url)) {
        console.warn(`[SECURITY] Blocked source file: ${req.url}`);
        return res.status(403).send('Forbidden');
    }
    next();
});

// Remove old CSP middleware fully since Helmet handles it
function proxyRequest(req, res, targetHost, targetPath, extraHeaders = {}) {
    if (res.headersSent) return;
    
    const targetUrl = `https://${targetHost}${targetPath}`;
    console.log(`[PROXY] ${req.method} ${req.url} -> ${targetUrl}`);
    
    const options = {
        hostname: targetHost,
        path: targetPath,
        method: req.method,
        headers: {
            ...req.headers,
            host: targetHost,
            ...extraHeaders
        },
        timeout: 0  

    };

    const proxyReq = https.request(options, (proxyRes) => {
        if (res.headersSent) return;
        
        if (proxyRes.statusCode && proxyRes.statusCode >= 300 && proxyRes.statusCode < 400 && proxyRes.headers.location) {
            const redirectUrl = new URL(proxyRes.headers.location);
            return proxyRequest(req, res, redirectUrl.hostname, redirectUrl.pathname + redirectUrl.search, extraHeaders);
        }
        
        res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
        proxyRes.pipe(res, { end: true });
    });

    proxyReq.on('error', (err) => {
        if (res.headersSent) return;
        console.error(`[PROXY ERROR] ${targetHost}:`, err.message);
        res.status(502).json({ code: -1, message: `Proxy error: ${err.message}` });
    });

    proxyReq.on('timeout', () => {
        if (res.headersSent) return;
        proxyReq.destroy();
        res.status(504).json({ code: -1, message: 'Proxy timeout' });
    });

    if (req.body) {
        req.pipe(proxyReq, { end: true });
    } else {
        proxyReq.end();
    }
}


app.use('/api-metadata', (req, res) => {
    const pathWithoutPrefix = req.url.startsWith('/') ? req.url : '/' + req.url;
    proxyRequest(
        req, res, 
        'h5-api.aoneroom.com', 
        '/wefeed-h5api-bff' + pathWithoutPrefix,
        { 'Origin': 'https://moviebox.ph', 'Referer': 'https://moviebox.ph/' }
    );
});

app.use('/api-player', (req, res) => {
    const pathWithoutPrefix = req.url.startsWith('/') ? req.url : '/' + req.url;
    proxyRequest(
        req, res, 
        '123movienow.cc', 
        '/wefeed-h5api-bff' + pathWithoutPrefix,
        { 'Origin': 'https://123movienow.cc', 'Referer': 'https://123movienow.cc/' }
    );
});

app.use('/api-cineverse', (req, res) => {
    const pathWithoutPrefix = req.url.startsWith('/') ? req.url : '/' + req.url;
    proxyRequest(
        req, res, 
        'cineverse.name.ng', 
        pathWithoutPrefix,
        { 'Origin': 'https://cineverse.name.ng', 'Referer': 'https://cineverse.name.ng/' }
    );
});

app.use('/api-omegatech', (req, res) => {
    const pathWithoutPrefix = req.url.startsWith('/') ? req.url : '/' + req.url;
    proxyRequest(
        req, res, 
        'omegatech-api.dixonomega.tech', 
        pathWithoutPrefix,
        { 'Origin': 'https://omegatech-api.dixonomega.tech', 'Referer': 'https://omegatech-api.dixonomega.tech/' }
    );
});

app.use('/api-stream', (req, res) => {
    
    let retries = 3;
    const originalReq = req;
    const tryProxy = async () => {
        try {
            
            let pathAfterPrefix = req.url.substring(12);
            try {
                pathAfterPrefix = decodeURIComponent(pathAfterPrefix);
            } catch (e) {
                console.error('[STREAM PROXY] Failed to decode:', pathAfterPrefix);
                return res.status(400).json({ error: 'Invalid URL' });
            }
            let targetHost = 'movieapi.giftedtech.co.ke';
            let targetPath = '/api/v2/stream';
            try {
                const urlObj = new URL(pathAfterPrefix);
                targetHost = urlObj.host;
                targetPath = urlObj.pathname + urlObj.search;
            } catch (e) {
                targetPath = pathAfterPrefix;
            }
            proxyRequest(req, res, targetHost, targetPath, { 'Origin': `https://${targetHost}`, 'Referer': `https://${targetHost}/` });
        } catch (err) {
            if (retries-- > 0) {
                console.log(`[RETRY STREAM] ${retries} left`);
                await new Promise(r => setTimeout(r, 1000));
                tryProxy();
            } else {
                res.status(502).json({ error: 'Stream unavailable, retrying...' });
            }
        }
    };
    tryProxy();
});
    
    

    
    console.log(`[STREAM PROXY] Original path: ${req.url}`);
    console.log(`[STREAM PROXY] Path after prefix: ${pathAfterPrefix}`);
    
    
    let targetHost = 'movieapi.giftedtech.co.ke';
    let targetPath = '/api/v2/stream';
    
    try {
        const urlObj = new URL(pathAfterPrefix);
        targetHost = urlObj.host;
        targetPath = urlObj.pathname + urlObj.search;
    } catch (e) {
        console.error('[STREAM PROXY] Invalid URL:', pathAfterPrefix);
        
        targetPath = pathAfterPrefix;
    }
    
    console.log(`[STREAM PROXY] Forwarding to ${targetHost}${targetPath}`);
    
    proxyRequest(
        req, res, 
        targetHost, 
        targetPath,
        { 'Origin': `https://${targetHost}`, 'Referer': `https://${targetHost}/` }
    );
});

console.log('[PROXY] API proxies ready: metadata/player/cineverse/stream');


app.use(express.static(path.join(__dirname, '../dist'), {
    maxAge: '1y',
    etag: true,
    setHeaders: (res, path) => {
        if (path.endsWith('.js')) res.set('Content-Type', 'application/javascript');
        if (path.endsWith('.css')) res.set('Content-Type', 'text/css');
    }
}));



    if (req.path.startsWith('/api') || req.path.startsWith('/socket.io')) {
        return next();
    }
    res.sendFile(path.join(__dirname, '../dist/index.html'));
});



app.get('/api/visitors', (req, res) => {
    res.json({
        onlineUsers: visitorData.onlineUsers,
        todayVisitors: visitorData.todayVisitors,
        totalVisitors: visitorData.totalVisitors,
        pageViews: visitorData.pageViews
    });
});


app.get('/_i18n/:lang/messages.json', (req, res) => {
    const lang = req.params.lang || 'en';
    const messagesPath = path.join(__dirname, 'public/_i18n', lang, 'messages.json');
    
    if (fs.existsSync(messagesPath)) {
        res.json(require(messagesPath));
    } else {
        res.json({});
    }
});


app.get('/manifest.webmanifest', (req, res) => {
    const manifestPath = path.join(__dirname, 'public', 'manifest.webmanifest');
    if (fs.existsSync(manifestPath)) {
        res.json(require(manifestPath));
    } else {
        res.json({ name: 'Sl-flix' });
    }
});


app.post('/api/event', express.json(), (req, res) => {
    const { type, data } = req.body;
    io.emit('event', { type, data, timestamp: Date.now() });
    res.json({ success: true });
});

app.get('/api/domain', (req, res) => {
    res.json({ domain: req.get('host') || 'localhost:3001' });
});


app.get(/^\/admin/, (req, res) => {
    res.status(404).json({ error: 'Route not found' });
});


const PORT = 3000;
httpServer.listen(PORT, "0.0.0.0", () => {
    console.log(`\n🚀 BUFFMOVIEZ Server running on http://localhost:${PORT}`);
    console.log(`📊 Full production app ready!`);
});

export default app;
