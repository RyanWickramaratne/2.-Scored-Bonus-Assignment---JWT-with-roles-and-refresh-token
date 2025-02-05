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

// JTW Package
const jwt = require('jsonwebtoken');

// JWT Secret Key
const JWTSECRET = '123'

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
    const token = jwt.sign(
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

    console.log('Token:', token);
    res.json({ token });
    
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









const port = 3000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
