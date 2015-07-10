var spawn = require("child_process").spawn;
var fs = require("fs");
var exec = require("child_process").exec;
var debug = require("debug");
var debugCA = debug("openvpn:ssl:ca");
var debugREQ = debug("openvpn:ssl:req");

var OpenVPNClass = function(conf) {
  // Private vars
  var self = this;

  // Private Functions
  var createSubjectString = function(clientName) {
    if(!self.config) return null;
    return '/C=' + self.config.subject.country +
      '/ST=' + self.config.subject.state +
      '/L=' + self.config.subject.city +
      '/O=' + self.config.subject.company +
      '/OU=' + self.config.subject.division +
      '/CN=' + clientName + self.config.subject.domainSuffix +
      '/emailAddress=' + self.config.subject.email;
  };
  var createUserConfigString = function(files, client, callback) {
    var config = files.sample.replace("%USER%", client).replace("%CERT%", files.cert).replace("%CA%", files.ca).replace("%KEY%", files.key);
    config = config.split("\r").join("").replace(/\n/g, "\r\n");
    callback(config);
  };

  // Public functions
  this.configure = function(newConfig) {
    var defaultConfig = {
      subject: {
        country: null,
        state: null,
        city: null,
        company: null,
        division: null,
        domainSuffix: null,
        email: null
      },
      path: {
        management: null,
        certificates: null,
        clientConfig: null,
        sslConfig: null,
        serverCerts: null
      },
      ssl: {
        keyBitSize: null,
        md: null,
        expireDays: null
      },
      debug: false
    };

    if(newConfig.subject.country)       defaultConfig.subject.country = newConfig.subject.country; else return false;
    if(newConfig.subject.state)         defaultConfig.subject.state = newConfig.subject.state; else return false;
    if(newConfig.subject.city)          defaultConfig.subject.city = newConfig.subject.city; else return false;
    if(newConfig.subject.company)       defaultConfig.subject.company = newConfig.subject.company; else return false;
    if(newConfig.subject.division)      defaultConfig.subject.division = newConfig.subject.division; else return false;
    if(newConfig.subject.domainSuffix)  defaultConfig.subject.domainSuffix = newConfig.subject.domainSuffix; else return false;
    if(newConfig.subject.email)         defaultConfig.subject.email = newConfig.subject.email; else return false;

    if(newConfig.path.management)       defaultConfig.path.management = newConfig.path.management; else return false;
    if(newConfig.path.certificates)     defaultConfig.path.certificates = newConfig.path.certificates; else return false;
    if(newConfig.path.clientConfig)     defaultConfig.path.clientConfig = newConfig.path.clientConfig; else return false;
    if(newConfig.path.sslConfig)        defaultConfig.path.sslConfig = newConfig.path.sslConfig; else return false;
    if(newConfig.path.serverCerts)      defaultConfig.path.serverCerts = newConfig.path.serverCerts; else return false;

    if(newConfig.ssl.keyBitSize)        defaultConfig.ssl.keyBitSize = newConfig.ssl.keyBitSize; else return false;
    if(newConfig.ssl.md)                defaultConfig.ssl.md = newConfig.ssl.md; else return false;
    if(newConfig.ssl.expireDays)       defaultConfig.ssl.expireDays = newConfig.ssl.expireDays; else return false;

    if(newConfig.debug)                 defaultConfig.debug = newConfig.debug;

    self.config = defaultConfig;
    return true;
  };
  this.generateClientSSL = function(clientName, callback) {
    if(!self.config) return false;

    var optsReq = [
      'req',
      '-newkey','rsa:' + self.config.ssl.keyBitSize,
      '-keyout', self.config.path.certificates + clientName + ".key",
      '-out', self.config.path.certificates + clientName + ".csr",
      '-nodes',
      '-subj', createSubjectString(clientName),
      '-config', self.config.path.sslConfig
    ];
    var optsCa = [
      'ca',
      '-batch',
      '-days', self.config.ssl.expireDays,
      '-out', self.config.path.certificates + clientName + ".crt",
      '-in', self.config.path.certificates + clientName + ".csr",
      '-md', self.config.ssl.md,
      '-config', self.config.path.sslConfig
    ];

    var childReq = spawn("openssl", optsReq);
    childReq.stdout.on('data', function(data) {
      debugREQ('[STDOUT] ' + data);
    });
    childReq.stderr.on('data', function(data) {
      debugREQ('[STDERR] ' + data);
    });
    childReq.on('close', function(code) {
      if(code == 1) {
        callback(new Error("openssl req failed"));
      } else {
        var childCa = spawn("openssl", optsCa);
        childCa.stdout.on('data', function(data) {
          debugCA('[STDOUT] ' + data);
        });
        childCa.stderr.on('data', function(data) {
          debugCA('[STDERR] ' + data);
        });
        childCa.on('close', function(code) {
          if(code == 1) {
            callback(new Error("openssl ca failed"));
          } else {
            callback(null);
          }
        });
      }
    });
  };
  this.getConnectedClients = function(callback) {
    if(!self.config) return false;
    var child = exec("echo 'status 3' | socat stdio " + self.config.path.management);
    var connected = [];
    child.stdout.on('data', function(data) {
      var lines = data.split("\n");
      for(var i = 0; i < lines.length; i++) {
        if(lines[i].split("\t")[0] == "CLIENT_LIST") {
          connected.push({
            name: lines[i].split("\t")[1],
            realip: lines[i].split("\t")[2],
            internalip: lines[i].split("\t")[3],
            bytes: {received: lines[i].split("\t")[4], sent: lines[i].split("\t")[5]},
            since: lines[i].split("\t")[7].replace("\r", "")
          });
        }
      }
    });
    child.on('close', function(code) {
      if(code == 0) {
        callback(null, connected);
      } else {
        callback(new Error("socat failed"), []);
      }
    });
  };
  this.getClientList = function(callback) {
    if(!self.config) return false;
    var clients = [];
    fs.readdir(self.config.path.certificates, function(err, files) {
      if(err) return callback(err, []);
      for(var i = 0; i < files.length; i++) {
        if(files[i].indexOf(".crt") !== -1)
          clients.push(files[i].replace(".crt", ""));
      }
      return callback(null, clients);
    });
  };
  this.revokeClient = function(client, callback) {
    if(!self.config) return false;
    self.clientExists(client, function(err, exists) {
      if(err) return callback(err, false);
      if(!exists) return callback(new Error("client not found"), false);
      var args = [
        'ca',
        '-revoke', self.config.path.certificates + client + ".crt",
        '-config', self.config.path.sslConfig
      ];
      var child = spawn("openssl", args);
      child.on('close', function(code) {
        if(code == 0) return callback(null, true);
        else return callback(new Error("openssl failed"), false);
      });
    });
  };
  this.generateCRL = function(database, config, callback) {
    if(!config) return false;
    var args = [
      'ca',
      '-keyfile', config.path.serverCerts + "ca.key",
      '-cert', config.path.serverCerts + "ca.crt",
      '-gencrl',
      '-out', config.path.serverCerts + "crl.pem",
      '-config', config.path.sslConfig
    ];
    var child = spawn("openssl", args);
    child.on('close', function(code) {
      if(code == 0) {
        callback(null, true);
      } else {
        callback(new Error("openssl failed (exit "+code+")"), false);
      }
    });
  };
  this.createUserConfig = function(client, callback) {
    if(!self.config) return false;

    var files = {sample: "", cert: "", ca: "", key: ""};
    self.clientExists(client, function(err, exists) {
      if(err) return callback(err, false);
      if(!exists) return callback(new Error("client not found"), false);

      var i = 4;
      fs.readFile(self.config.path.clientConfig, "utf8", function(err, data) {
        if(err) return callback(err, false);
        files.sample = data;
        i--; !i && (createUserConfigString(files, client, function(config) {callback(false, config);}));
      });
      fs.readFile(self.config.path.serverCerts + "ca.crt", "utf8", function(err, data) {
        if(err) return callback(err, false);
        files.ca = "\r\n"+data;
        i--; !i && (createUserConfigString(files, client, function(config) {callback(false, config);}));
      });
      fs.readFile(self.config.path.certificates + client + ".crt", "utf8", function(err, data) {
        if(err) return callback(err, false);
        data = "-----BEGIN CERTIFICATE-----" + data.split("-----BEGIN CERTIFICATE-----")[1].split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\r\n";
        files.cert = "\r\n"+data;
        i--; !i && (createUserConfigString(files, client, function(config) {callback(false, config);}));
      });
      fs.readFile(self.config.path.certificates + client + ".key", "utf8", function(err, data) {
        if(err) return callback(err, false);
        files.key = "\r\n"+data;
        i--; !i && (createUserConfigString(files, client, function(config) {callback(false, config);}));
      });
    });
  };
  this.clientExists = function(client, callback) {
    if(!self.config) return false;
    self.getClientList(function(err, clients) {
      if(err) return callback(err, false);
      for(var i = 0; i < clients.length; i++) {
        if(clients[i] == client) return callback(null, true);
      }
      return callback(null, false);
    });
  };
  this.deleteClient = function(client, callback) {
    if(!config) return false;
    self.revokeClient(client, function(err, success) {
      if(err) return res.send({error: true, errmsg: err.toString()});
      if(!success) return res.send({error: true, errmsg: "couldn't revoke client"});
      //fs.unlink()
    });
  };

  // Public vars
  this.config = null;

  // Execute
  if(conf) this.configure(conf);
};

module.exports = function(conf) {return new OpenVPNClass(conf);};
