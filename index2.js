var express = require('express');
var app = express();
var path = require('path');
var bodyParser = require('body-parser');
var fs = require('fs');
var url = require('url');
var axios = require('axios');
var passport = require('passport');
var Saml2js = require('saml2js');
var SamlStrategy = require('passport-saml').Strategy;

//SAML Strategy
var saml = passport.use(new SamlStrategy(
{
    path: '/login/callback',
    entryPoint: 'https://pingfedtest.regeneron.com/idp/SSO.saml2',
    issuer: 'localhost.myapp'
},
function(profile, done) {
    // findByEmail(profile.email, function(err, user) {
    // if (err) {
    //     return done(err);
    // }
    // return done(null, user);
    // });
    //console.log(profile);
    return done(null, profile);
})
);

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
	done(null, user);
});

passport.deserializeUser((user, done) => {
	done(null, user);
});

// create application/json parser
var jsonParser = bodyParser.json();
// create application/x-www-form-urlencoded parser
var urlencodedParser = bodyParser.urlencoded({ extended: false });

app.post('/saveConfigure', jsonParser, (req, res) => {
    console.log('printing req body');
    console.log(req.body);
    let oauthDetails = req.body;
    fs.writeFile('idpConfig.json', JSON.stringify(oauthDetails), ()=>{
        console.log('IDP Configuration save to idpConfig.json file.');
    });
    res.status(200).send('All form submitted');
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname + '/html_files/welcome.html'));
});

app.get('/authCode', (req, res) => {
    fs.readFile('./idpConfig.json', (err, data) => {
        if(!err){
            let idpData = JSON.parse(data);
            res.redirect(url.format({
                pathname: idpData.authEndpoint,
                query: {
                    'client_id': idpData.client_id,
                    'response_type': 'code',
                    'response_mode': 'query',
                    'scope': 'openid profile',
                    'redirect_uri': 'http://localhost:8080/authCodeValidator',
                    'state': "logged_in",
                    'nonce': "somerandomstring"
                }
            }))
        }else{
            res.status(400).send('Bad Request: '+err);
        }
    });
});

app.get('/authCodeValidator', (req, res) => {
    let code = req.query.code;
    let state = req.query.state;
    // || url.parse(req.protocol+'://'+req.hostname+''+req.originalUrl,true, true)
    //console.log(state);
    if(state==='logged_in'){
        if(code!==null||code!==''){
            fs.readFile('./idpConfig.json', (err, data) => {
                if(!err){
                    let idpData = JSON.parse(data);
                    let client_id = idpData.client_id;
                    let client_Secret = idpData.client_secret;
                    let clientCredentials = new Buffer(''+client_id+':'+client_Secret);
                    let base64ClientCredentials = clientCredentials.toString('base64');
                    let headers = {
                        'Authorization': 'Basic '+base64ClientCredentials,
                        'Accept': 'application/json',
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Connection': 'close',
                        'Content-Length': '0'
                    };
                    // axios.post(idpData.tokenEndpoint, {
                        // grant_type: 'authorization_code',
                        // redirect_uri: 'http://localhost:8080/showTokens',
                        // code: code
                    // },headers)
                    axios({
                        method: 'post',
                        url: idpData.tokenEndpoint,
                        params: {
                            'grant_type': 'authorization_code',
                            'redirect_uri': 'http://localhost:8080/authCodeValidator',
                            'code': code
                        },
                        headers:{
                            'Authorization': 'Basic '+base64ClientCredentials,
                            'Accept': 'application/json',
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'Connection': 'close',
                            'Content-Length': '0' 
                        }
                    })
                    .then((resAxios) => {
                        console.log(resAxios);
                        res.status(200).send(resAxios.data);
                    })
                    .catch(err => {
                        console.log(err);
                        res.status(400).send('Bad Request: '+err);
                    });
                }else{
                    res.status(400).send('Bad Request: '+err);
                }
            });
        }else{
            res.status(400).send("Invalid Code returned from IDP: "+state);  
        }
    }else{

        res.status(400).send("Invalid State: "+state);
    }
});

app.get('/implicit', (req, res) => {
    fs.readFile('./idpConfig.json', (err, data) => {
        if(!err){
            let idpData = JSON.parse(data);
            res.redirect(url.format({
                pathname: idpData.authEndpoint,
                query: {
                    'client_id': idpData.client_id,
                    'response_type': 'token',
                    'scope': 'openid profile',
                    'redirect_uri': 'http://localhost:8080/authCodeValidator',
                    'state': "logged_in",
                    'nonce': "somerandomstring"
                }
            }))
        }else{
            res.status(400).send('Bad Request: '+err);
        }
    });
});

app.get('/clientCredentials', (req, res) => {
    fs.readFile('./idpConfig.json', (err, data) => {
        if(!err){
            let idpData = JSON.parse(data);
            let client_id = idpData.client_id;
            let client_Secret = idpData.client_secret;
            let clientCredentials = new Buffer(''+client_id+':'+client_Secret);
            let base64ClientCredentials = clientCredentials.toString('base64');
            axios({
                method: 'post',
                url: idpData.tokenEndpoint,
                params: {
                    'grant_type': 'client_credentials',
                    'scope': 'custom_scope_1',
                },
                headers:{
                    'Authorization': 'Basic '+base64ClientCredentials,
                    'Accept': 'application/json',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'cache-control': 'no-cache'
                }
            })
            .then((resAxios) => {
                console.log(resAxios);
                res.status(200).send(resAxios.data);
            })
            .catch(err => {
                console.log(err);
                res.status(400).send('Bad Request: '+err);
            });
        }else{
            res.status(400).send('Bad Request: '+err);
        }
    });
});

app.get('/login',
  passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
  function(req, res) {
    res.redirect('/');
  }
);

app.get('/home', (req, res) => {
    let samlResponse;
    if(req.params.saml){
        samlResponse = req.params.saml;
        res.send(samlResponse);
    }else{
        res.status(400).send('Bad Request: Missing SAML Response');
    }
}
  
);

app.post('/login/callback',
  bodyParser.urlencoded({ extended: false }),
  passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
  function(req, res) {
      //console.log(req.user);
      //console.log(req.body.done);
        res.json(req.user);
  }
);

app.listen(process.env.PORT || 3000, ()=> {
    console.log('Server is up and listening on port 8080');
});