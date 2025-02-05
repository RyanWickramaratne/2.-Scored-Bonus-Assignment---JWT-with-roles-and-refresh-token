const express = require('express');
const app = express();

const cors = require('cors');
app.use(cors());

app.use(express.json());


// ------------------- HardCoded Database -------------------
const users = [
    {username: 'Ryan', password: 'Ryan@123', role: 'admin'},
    {username: 'Lasse', password: 'Lasse@123', role: 'user'}
]


// JTW Package
const jwt = require('jsonwebtoken');

// Secret Keys
const JWTSECRET = '123';
const REFRESH_SECRET = '456';

// Store refresh tokens
let refreshTokens = [];


// ------------------- ROUTES -------------------

// Use HTTP Basic Authentication for login
function httpBasicAuth (req, res, next) {

    // Get the Authorization header
    const authfileds = req.get('Authorization');
    console.log('Authorization:', authfileds);

    if(!authfileds)
    {
        res.status(401).json({message: 'Authorization Header Not Found'});
        return;
    }

    try
    {
        const authParts = authfileds.split(' ')[1];    

        // Get the base 64 encoded string and convert it
        // Create a buffer from the string
        let bufferObj = Buffer.from(authParts, "base64");

        // Encode the Buffer as a utf8 string
        let decodedString = bufferObj.toString("utf8");

        console.log("The decoded string:", decodedString);

        // Isolate Username and Password
        const username = decodedString.split(':')[0];
        const password = decodedString.split(':')[1];

        // attach the username and password to the request object
        req.user = {username, password};
        
        next();
    }
    catch(err)
    {
        res.status(401).json({message: err.message});
    }
    
}


//Login Route
app.post('/sign-in', httpBasicAuth , (req, res) => {

    // Chech the req.user object's username and password
    console.log('User:', req.user);

    /// Find user in the database
    const foundUser = users.find((element) => element.username === req.user.username && element.password === req.user.password);
    console.log('Found User:', foundUser);

    if (!foundUser) {
        return res.status(401).json({message: 'Invalid Credentials'});
    }

    console.log('Login Successful');

    // Create JWT Token with the correct role
    const accessToken = jwt.sign(
        // Payload
        {
            username: foundUser.username,
            role: foundUser.role
        },
        // Secret Key
        JWTSECRET,
        // Other Options
        {
            expiresIn: '15m'
        }
    
    );

    const refreshToken = jwt.sign(
        // Payload
        { username: foundUser.username },
        // Secret Key
        REFRESH_SECRET,
        // Other Options
        {
            expiresIn: '7d'
        }
    );

    console.log('Access Token:', accessToken);
    console.log('Refresh Token:', refreshToken);

    // Store the refresh token
    refreshTokens.push(refreshToken);
    console.log('Added Refresh Tokens:', refreshTokens);

    // Send the tokens to the client
    res.json({ accessToken, refreshToken });
    
});



// Do the JWT Authentication Part

// JWT Authentication
function authenticateToken (req, res, next){

    console.log('Authenticating Token');

    // Get the Authorization Header
    const authfileds = req.get('Authorization');
    console.log(authfileds);

    if(!authfileds)
    {
        res.status(401).json({message: 'Authorization Header Not Found'});
        return;
    }

    // get the token part
    const tokenPart = authfileds.split(' ')[1];
    console.log(tokenPart);

    
    // Verify the token
    try
    {
        const decoded = jwt.verify(tokenPart, JWTSECRET);
        console.log(decoded);
        // Attach the decoded object to the request object
        req.user = decoded;
        next();
    }
    catch(err)
    {
        res.status(401).json({message: err.message});
    }    

}

// Hardcoded posrs
const posts = ['Early bird catches the worm']

app.get('/posts', authenticateToken, (req, res) => {
    
    console.log('Posts Route');

    // Check the user object
    console.log('User:', req.user);

    //Show the Posts
    res.json(posts);
});


app.post('/posts', authenticateToken, (req, res) => {

    if (!req.body.post) {
        return res.status(400).json({ message: 'Post content is required' });
    }

    if(req.user.role !== 'admin')
    {
        res.status(403).json({message: 'Forbidden'});
        return;
    }
    else
    {
        // Add a new post
        const newPost = req.body.post;
        posts.push(newPost);
        res.json({
            message: 'Post Added',
            posts: posts
        });
    }

});



// Refresh Token Route (Generates New Access Token)
app.post('/refresh-token', (req, res) => {

    // Get the refresh token from the request body
    const { token } = req.body;
    if (!token) {
        return res.status(401).json({ message: 'Refresh Token Required' });
    }

    // Check if the refresh token is valid
    if (!refreshTokens.includes(token)) {
        return res.status(403).json({ message: 'Invalid Refresh Token' });
    }

    // Verify the refresh token
    try 
    {
        const decoded = jwt.verify(token, REFRESH_SECRET);
        console.log("Decoded: ", decoded);

        // Check if the user exists
        const user = users.find(element => element.username === decoded.username);
        console.log("User: ", user);
        if (!user) {
            return res.status(403).json({ message: 'User Not Found' });
        }

        // Create a new access token
        const newAccessToken = jwt.sign(
            { 
                username: user.username, 
                role: user.role 
            }, 
            JWTSECRET,
            { expiresIn: '15m' }
        );

        res.json({ accessToken: newAccessToken });
    } 
    catch (err) 
    {
        res.status(403).json({ message: err.message });
    }
});

// Logout Route
app.post('/logout', (req, res) => {

    // See the refresh tokens
    console.log("Before tokens: ", refreshTokens);

    if (!req.body.token) {
        return res.status(401).json({ message: 'Refresh Token Required' });
    }

    // Check if the refresh token is valid
    if (!refreshTokens.includes(req.body.token)) {
        return res.status(403).json({ message: 'Invalid Refresh Token' });
    }

    // Remove the refresh token from the refreshTokens array
    refreshTokens = refreshTokens.filter((element) => element !== req.body.token);
    console.log("After tokens: ", refreshTokens);

    res.json({ message: 'Refresh Token Deleted' });
});





const port = 3000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
