require('dotenv').config();

const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');
const session = require('express-session');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Sessions
app.use(session({
    secret: process.env.SESSION_SECRET || 'keyboardcat',
    resave: false,
    saveUninitialized: false, // Changed to false for better security
    rolling: true, // Reset expiration on each request
    cookie: {
        secure: false, // Set to true if using HTTPS
        httpOnly: true, // Prevent XSS attacks
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'lax' // CSRF protection
    },
    name: 'racetrack.sid' // Custom session name
}));

app.use((req, res, next) => {
    // Check for session timeout (24 hours)
    if (req.session && req.session.loginTime) {
        const sessionAge = Date.now() - req.session.loginTime;
        const maxAge = 24 * 60 * 60 * 1000; // 24 hours

        if (sessionAge > maxAge) {
            console.log('Session expired for user:', req.session.userRole);
            req.session.destroy(() => {
                console.log('Expired session destroyed');
            });
        }
    }
    next();
});

app.use((req, res, next) => {
    if (req.path.includes('/front-desk') || req.path.includes('/race-control') || req.path.includes('/lap-line-tracker')) {
        res.set({
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        });
    }
    next();
});

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// ---- Authentication Middleware ----
function requireAuth(role) {
    return (req, res, next) => {
        console.log(`Checking ${role} authentication for IP: ${req.ip}`);
        console.log('Session ID:', req.sessionID);
        console.log('Session exists:', !!req.session);

        // Check if session exists at all
        if (!req.session) {
            console.log('❌ No session found');
            return res.redirect('/');
        }

        // Check if session has been destroyed/expired
        if (req.session.destroyed) {
            console.log('❌ Session has been destroyed');
            return res.redirect('/');
        }

        let isAuthenticated = false;

        switch (role) {
            case 'receptionist':
                isAuthenticated = req.session.isReceptionist === true;
                break;
            case 'safety':
                isAuthenticated = req.session.isSafety === true;
                break;
            case 'observer':
                isAuthenticated = req.session.isObserver === true;
                break;
        }

        if (isAuthenticated) {
            console.log(`✅ Authorized ${role} access from IP: ${req.ip}`);
            next(); // User is authenticated, continue to the page
        } else {
            console.log(`❌ Unauthorized ${role} access attempt from IP: ${req.ip}`);
            console.log('Session state:', {
                isReceptionist: req.session.isReceptionist,
                isSafety: req.session.isSafety,
                isObserver: req.session.isObserver,
                sessionID: req.sessionID
            });
            res.redirect('/'); // Redirect to homepage/login
        }
    };
}

// ---- State ----
let state = {
    raceMode: 'idle',       // idle, countdown, racing, finished
    flag: 'green',          // green, yellow, red, etc.
    currentRace: null,
    lastResults: [],
    lapObserverActive: false
};

let raceTimer = null;
let raceSessions = []; // Array of race sessions
let nextSessionId = 1;
const allCars = [
    'Audi', 'BMW', 'Mazda', 'Lada',
    'Ferrari', 'Porsche', 'Mercedes', 'Toyota',
    'Honda', 'Nissan', 'Ford', 'Volkswagen'
];

// ---- Routes ----

// Home/Leaderboard (public)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'leader-board.html'));
});

// Unified staff login
app.post('/login', (req, res) => {
    const { password } = req.body;

    console.log('Login attempt from IP:', req.ip);

    // Clear any existing session data first
    req.session.isReceptionist = false;
    req.session.isSafety = false;
    req.session.isObserver = false;

    if (password === process.env.RECEPTIONIST_KEY) {
        req.session.isReceptionist = true;
        req.session.loginTime = Date.now();
        req.session.userRole = 'receptionist';
        console.log('✅ Receptionist login successful');
        return res.json({ success: true, redirect: '/front-desk.html' });

    } else if (password === process.env.SAFETY_KEY) {
        req.session.isSafety = true;
        req.session.loginTime = Date.now();
        req.session.userRole = 'safety';
        console.log('✅ Safety login successful');
        return res.json({ success: true, redirect: '/race-control' });

    } else if (password === process.env.OBSERVER_KEY) {
        req.session.isObserver = true;
        req.session.loginTime = Date.now();
        req.session.userRole = 'observer';
        state.lapObserverActive = true;
        console.log('✅ Observer login successful');
        return res.json({ success: true, redirect: '/lap-line-tracker' });

    } else {
        console.log('❌ Invalid login attempt');
        return res.json({ success: false, error: 'Invalid credentials' });
    }
});

// Logout route
app.post('/logout', (req, res) => {
    console.log('Logout requested by session:', req.sessionID);
    console.log('Session before destruction:', {
        isReceptionist: req.session.isReceptionist,
        isSafety: req.session.isSafety,
        isObserver: req.session.isObserver
    });

    // Handle observer logout - disable lap observer
    if (req.session.isObserver) {
        state.lapObserverActive = false;
        console.log('Lap observer deactivated');
    }

    // Destroy the session
    req.session.destroy((err) => {
        if (err) {
            console.error('Session destruction error:', err);
            return res.status(500).json({
                success: false,
                error: 'Logout failed',
                details: err.message
            });
        }

        // Clear the session cookie with CORRECT NAME
        res.clearCookie('racetrack.sid', {  // ✅ Fixed: Use correct cookie name
            path: '/',
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'  // Add this for better security
        });

        console.log('✅ Session destroyed and cookie cleared');

        // Add cache-control headers to prevent caching
        res.set({
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        });

        res.json({
            success: true,
            message: 'Logged out successfully'
        });
    });
});

// Public display routes (no authentication required)
app.get('/leader-board', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'leader-board.html'));
});

app.get('/next-race', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'next-race.html'));
});

app.get('/race-countdown', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'race-countdown.html'));
});

app.get('/race-flags', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'race-flags.html'));
});

// Protected routes - each requires specific role
app.get('/front-desk.html', requireAuth('receptionist'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'front-desk.html'));
});

app.get('/race-control', requireAuth('safety'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'race-control.html'));
});

app.get('/lap-line-tracker', requireAuth('observer'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'lap-line-tracker.html'));
});

// Optional: API endpoints to check authentication status
app.get('/api/check-auth/receptionist', (req, res) => {
    const isAuthenticated = req.session.isReceptionist === true;
    console.log('Receptionist auth check:', isAuthenticated);

    if (isAuthenticated) {
        res.status(200).json({
            authenticated: true,
            role: 'receptionist',
            loginTime: req.session.loginTime,
            sessionId: req.sessionID
        });
    } else {
        res.status(401).json({ authenticated: false });
    }
});

app.get('/api/check-auth/safety', (req, res) => {
    const isAuthenticated = req.session.isSafety === true;
    console.log('Safety auth check:', isAuthenticated);

    if (isAuthenticated) {
        res.status(200).json({
            authenticated: true,
            role: 'safety',
            loginTime: req.session.loginTime,
            sessionId: req.sessionID
        });
    } else {
        res.status(401).json({ authenticated: false });
    }
});

app.get('/api/check-auth/observer', (req, res) => {
    const isAuthenticated = req.session.isObserver === true;
    console.log('Observer auth check:', isAuthenticated);

    if (isAuthenticated) {
        res.status(200).json({
            authenticated: true,
            role: 'observer',
            loginTime: req.session.loginTime,
            sessionId: req.sessionID
        });
    } else {
        res.status(401).json({ authenticated: false });
    }
});

// ---- Add a general auth status endpoint ----
app.get('/api/auth-status', (req, res) => {
    const authStatus = {
        authenticated: false,
        role: null,
        sessionId: req.sessionID,
        loginTime: req.session.loginTime || null
    };

    if (req.session.isReceptionist) {
        authStatus.authenticated = true;
        authStatus.role = 'receptionist';
    } else if (req.session.isSafety) {
        authStatus.authenticated = true;
        authStatus.role = 'safety';
    } else if (req.session.isObserver) {
        authStatus.authenticated = true;
        authStatus.role = 'observer';
    }

    console.log('Auth status check:', authStatus);
    res.json(authStatus);
});


io.on('connection', (socket) => {
    console.log('Client connected');

    // Send initial state
    socket.emit('state_update', getClientState());
    // Send current sessions
    socket.emit('sessions_update', raceSessions);

    // Enhanced Admin events with validation
    socket.on('admin_start_countdown', () => {
        if (!state.currentRace) {
            socket.emit('error_message', 'No race session selected');
            return;
        }

        if (state.raceMode !== 'idle') {
            socket.emit('error_message', 'Race must be in idle state to start countdown');
            return;
        }

        state.raceMode = 'countdown';
        console.log('Race countdown started by race control');
        io.emit('state_update', getClientState());
    });

    socket.on('admin_start_race', () => {
        if (!state.currentRace) {
            socket.emit('error_message', 'No race session selected');
            return;
        }

        if (state.raceMode !== 'idle' && state.raceMode !== 'countdown') {
            socket.emit('error_message', 'Race must be in idle or countdown state to start');
            return;
        }

        state.raceMode = 'racing';
        state.currentRace.startTime = Date.now();

        // 🔥 UPDATED: Use RACE_TIMER_MINUTES instead of NODE_ENV
        const raceMinutes = parseInt(process.env.RACE_TIMER_MINUTES) || 10; // Default to 10 minutes
        const raceDuration = raceMinutes * 60 * 1000; // Convert to milliseconds

        console.log(`🏁 Race started with ${raceMinutes} minute duration`);

        // Remove the session from available sessions once race starts
        const sessionIndex = raceSessions.findIndex(s => s.id === state.currentRace.id);
        if (sessionIndex !== -1) {
            const removedSession = raceSessions.splice(sessionIndex, 1)[0];
            console.log(`✅ Session "${removedSession.name}" removed from available sessions (race started)`);
            // Immediately notify all front desk clients about the updated sessions list
            io.emit('sessions_update', raceSessions);
        }

        raceTimer = setTimeout(() => {
            state.raceMode = 'finished';
            console.log('Race automatically finished after time limit');
            io.emit('state_update', getClientState());
        }, raceDuration);

        console.log('Race started by race control');
        io.emit('state_update', getClientState());
    });

    socket.on('admin_set_flag', (flag) => {
        state.flag = flag;
        console.log(`Flag changed to: ${flag}`);
        io.emit('state_update', getClientState());
    });

    socket.on('admin_set_next_race', (sessionId) => {
        const session = raceSessions.find(s => s.id === sessionId);
        if (!session) {
            socket.emit('error_message', 'Session not found');
            return;
        }

        if (session.drivers.length === 0) {
            socket.emit('error_message', 'Cannot start race: No drivers in session');
            return;
        }

        if (state.raceMode === 'racing') {
            socket.emit('error_message', 'Cannot change session: Race in progress');
            return;
        }

        // Reset any previous race data
        if (raceTimer) {
            clearTimeout(raceTimer);
            raceTimer = null;
        }

        state.currentRace = {
            ...session,
            laps: {},
            startTime: null
        };
        state.raceMode = 'idle';
        state.flag = 'green';

        console.log(`Race session set to: ${session.name} (${session.drivers.length} drivers)`);
        io.emit('state_update', getClientState());
    });

    // Add the enhanced finish race handler
    socket.on('admin_finish_race', () => {
        if (state.raceMode !== 'racing') {
            socket.emit('error_message', 'No active race to finish');
            return;
        }

        if (raceTimer) {
            clearTimeout(raceTimer);
            raceTimer = null;
        }

        state.raceMode = 'finished';
        console.log('Race manually finished by race control');
        io.emit('state_update', getClientState());
    });

    socket.on('record_lap', ({ driverName, lapTime }) => {
        console.log(`Lap recorded: ${driverName} - ${lapTime}ms`);

        if (!state.currentRace || state.raceMode !== 'racing') {
            socket.emit('error_message', 'No active race to record lap');
            return;
        }

        // Validate driver exists in current race
        const driverExists = state.currentRace.drivers.find(d => d.name === driverName);
        if (!driverExists) {
            socket.emit('error_message', `Driver ${driverName} not found in current race`);
            return;
        }

        // Initialize driver's lap array if it doesn't exist
        if (!state.currentRace.laps[driverName]) {
            state.currentRace.laps[driverName] = [];
        }

        // Add the lap time
        state.currentRace.laps[driverName].push(lapTime);

        const lapNumber = state.currentRace.laps[driverName].length;

        console.log(`✅ Lap ${lapNumber} recorded for ${driverName}: ${(lapTime/1000).toFixed(3)}s`);

        // Emit lap update to all clients
        io.emit('lap_update', {
            driverName,
            lapTime,
            lapNumber,
            totalLaps: state.currentRace.laps[driverName].length
        });

        io.emit('state_update', getClientState());
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected');
    });

    // Session management (Front Desk functions)
    socket.on('add_session', (name) => {
        const session = { id: nextSessionId++, name, drivers: [] };
        raceSessions.push(session);
        console.log(`New session created: ${name}`);
        io.emit('sessions_update', raceSessions);
    });

    socket.on('remove_session', (sessionId) => {
        const sessionIndex = raceSessions.findIndex(s => s.id === sessionId);
        if (sessionIndex !== -1) {
            const removedSession = raceSessions.splice(sessionIndex, 1)[0];
            console.log(`Session removed: ${removedSession.name}`);
            io.emit('sessions_update', raceSessions);
        }
    });

    socket.on('add_driver', ({ sessionId, driverName, car }) => {
        const session = raceSessions.find(s => s.id === sessionId);
        if (!session) {
            socket.emit('error_message', 'Session not found');
            return;
        }

        // Enhanced validation
        if (!driverName || typeof driverName !== 'string' || driverName.trim().length < 2) {
            socket.emit('error_message', 'Driver name must be at least 2 characters');
            return;
        }

        if (driverName.length > 30) {
            socket.emit('error_message', 'Driver name too long (max 30 characters)');
            return;
        }

        if (!/^[a-zA-Z\s\-']+$/.test(driverName)) {
            socket.emit('error_message', 'Driver name contains invalid characters');
            return;
        }

        // Check for maximum drivers per session
        if (session.drivers.length >= 8) {
            socket.emit('error_message', 'Maximum 8 drivers per session');
            return;
        }

        // Unique driver name check (case-insensitive)
        if (session.drivers.some(d => d.name.toLowerCase() === driverName.trim().toLowerCase())) {
            socket.emit('error_message', 'Driver name must be unique in this session');
            return;
        }

        // Validate car if provided
        if (car && !allCars.includes(car)) {
            socket.emit('error_message', 'Invalid car selection');
            return;
        }

        // Check car availability
        if (car && session.drivers.some(d => d.car === car)) {
            socket.emit('error_message', 'Car already assigned to another driver');
            return;
        }

        // FIXED: Random auto-assign car if not provided
        if (!car) {
            const usedCars = session.drivers.map(d => d.car).filter(Boolean);
            const availableCars = allCars.filter(c => !usedCars.includes(c));

            if (availableCars.length > 0) {
                // Always assign a random car immediately
                const randomIndex = Math.floor(Math.random() * availableCars.length);
                car = availableCars[randomIndex];
                console.log(`Auto-assigned ${car} to ${driverName.trim()}`);
            } else {
                // Fallback: if all cars taken, assign a random car anyway (shared cars)
                const randomIndex = Math.floor(Math.random() * allCars.length);
                car = allCars[randomIndex];
                console.log(`All cars taken, assigned ${car} to ${driverName.trim()} (shared)`);
            }
        }

        session.drivers.push({ name: driverName.trim(), car });
        console.log(`Driver added: ${driverName.trim()} → ${car || 'No car assigned'} in session ${session.name}`);
        io.emit('sessions_update', raceSessions);
    });

    socket.on('remove_driver', ({ sessionId, driverName }) => {
        const session = raceSessions.find(s => s.id === sessionId);
        if (!session) return;
        session.drivers = session.drivers.filter(d => d.name !== driverName);
        console.log(`Driver removed: ${driverName} from session ${session.name}`);
        io.emit('sessions_update', raceSessions);
    });

    socket.on('update_driver_car', ({ sessionId, driverName, car }) => {
        const session = raceSessions.find(s => s.id === sessionId);
        if (!session) return;

        const driver = session.drivers.find(d => d.name === driverName);
        if (!driver) return;

        if (car === 'auto-assign' || !car) {
            // Random assignment when switching to auto-assign
            const usedCars = session.drivers
                .filter(d => d.name !== driverName)
                .map(d => d.car)
                .filter(Boolean);
            const availableCars = allCars.filter(c => !usedCars.includes(c));

            if (availableCars.length > 0) {
                const randomIndex = Math.floor(Math.random() * availableCars.length);
                driver.car = availableCars[randomIndex];
                console.log(`Auto-assigned ${driver.car} to ${driverName}`);
            } else {
                // If no cars available, assign random anyway
                const randomIndex = Math.floor(Math.random() * allCars.length);
                driver.car = allCars[randomIndex];
                console.log(`Auto-assigned ${driver.car} to ${driverName} (shared)`);
            }
        } else {
            // Manual assignment
            if (session.drivers.some(d => d.name !== driverName && d.car === car)) {
                socket.emit('error_message', 'Car already assigned to another driver');
                return;
            }
            driver.car = car;
            console.log(`Manually assigned ${car} to ${driverName}`);
        }

        io.emit('sessions_update', raceSessions);
    });
});

// ---- Helper ----
function getClientState() {
    return {
        raceMode: state.raceMode,
        flag: state.flag,
        currentRace: state.currentRace ? {
            id: state.currentRace.id,
            name: state.currentRace.name,
            drivers: state.currentRace.drivers,
            startTime: state.currentRace.startTime,
            laps: state.currentRace.laps
        } : null,
        lastResults: state.lastResults
    };
}

// ---- Start ----
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0'; // Bind to all network interfaces

server.listen(PORT, HOST, () => {
    const networkInterfaces = require('os').networkInterfaces();
    const addresses = [];

    // Get all available IP addresses
    Object.keys(networkInterfaces).forEach(interfaceName => {
        networkInterfaces[interfaceName].forEach(interface => {
            if (!interface.internal && interface.family === 'IPv4') {
                addresses.push(interface.address);
            }
        });
    });

    console.log(`🚀 Server running on port ${PORT}`);
    console.log('📱 Access from any device using these URLs:');
    console.log(`   - Local: http://localhost:${PORT}`);

    addresses.forEach(ip => {
        console.log(`   - Network: http://${ip}:${PORT}`);
    });

    console.log('\n🖥️  Public Displays:');
    addresses.forEach(ip => {
        console.log(`   - Leader Board: http://${ip}:${PORT}/leader-board`);
        console.log(`   - Next Race: http://${ip}:${PORT}/next-race`);
        console.log(`   - Race Countdown: http://${ip}:${PORT}/race-countdown`);
        console.log(`   - Race Flags: http://${ip}:${PORT}/race-flags`);
    });

    console.log('\n🔒 Protected Admin Interfaces:');
    addresses.forEach(ip => {
        console.log(`   - Front Desk: http://${ip}:${PORT}/front-desk.html`);
        console.log(`   - Race Control: http://${ip}:${PORT}/race-control`);
        console.log(`   - Lap Tracker: http://${ip}:${PORT}/lap-line-tracker`);
    });

    console.log('\n🔐 Authentication required for admin interfaces');
});