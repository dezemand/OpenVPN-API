/**
 * Created by Mand on 10-7-2015.
 */

var express = require("express");
var config = require("./config.json");
var openvpn = require("./libs/openvpn")(config);
var debug = require("debug")("openvpn:app");
var bodyParser = require("body-parser");

var app = express();
app.set("x-powered-by", false);

app.use(bodyParser.json());

app.get("/", function(req, res) {
  res.send({error: true, errmsg: "redirect to documentation"});
});

// /user
app.use("/user/:user", function(req, res, next) {
  openvpn.clientExists(req.params.user, function(err, exists) {
    if(err) return res.send({error: true, errmsg: err.toString()});
    req.exists = exists;
    next();
  });
});
app.get("/user/:user/config", function(req, res) {
  debug("Getting config for " + req.params.user);
  if(!req.exists) return res.send({error: true, errmsg: "user doesnt exists"});
  openvpn.createUserConfig(req.params.user, function(err, config) {
    if(err) return res.send({error: true, errmsg: err.toString()});
    res.set("Content-Type", "application/ovpn");
    res.set("Content-Disposition", "attachment; filename=\"" + req.params.user + ".ovpn\"");
    res.send(config);
  });
});
app.get("/user/:user/revoke", function(req, res) {
  if(!req.exists) return res.send({error: true, errmsg: "user doesnt exists"});
  openvpn.revokeClient(req.params.user, function(err, success) {
    if(err) return res.send({error: true, errmsg: err.toString()});
    if(!success) return res.send({error: true, errmsg: "couldn't revoke user"});
    res.send({error: false, revokedUser: req.params.user});
  });
});
app.delete("/user/:user", function(req, res) {
  if(!req.exists) return res.send({error: true, errmsg: "user doesnt exists"});
  openvpn.deleteClient(req.params.user, function(err) {
    if(err) return res.send({error: true, errmsg: err.toString()});
    res.send({error: false, deletedUser: req.params.user});
  });
});

// /users
app.get("/users/list", function(req, res) {
  openvpn.getClientList(function(err, list) {
    if(err) return res.send({error: true, errmsg: err.toString()});
    res.send({error: false, list: list});
  });
});
app.get("/users/connected", function(req, res) {
  openvpn.getConnectedClients(function(err, list) {
    if(err) return res.send({error: true, errmsg: err.toString()});
    res.send({error: false, list: list});
  });
});
app.post("/users/create", function(req, res) {
  if(!req.body.name) res.send({error: true, errmsg: "no `name` parameter"});
  openvpn.clientExists(req.body.name, function(err, exists) {
    if(err) return res.send({error: true, errmsg: err.toString()});
    if(exists) return res.send({error: true, errmsg: "user already exists"});
    openvpn.generateClientSSL(req.body.name, function(err) {
      if(err) return res.send({error: true, errmsg: err.toString()});
      res.send({error: false, userCreated: req.body.name});
    });
  });
});

// 404
app.use(function(req, res) {
  res.send({error: true, errmsg: "invalid uri"});
});

module.exports = app;