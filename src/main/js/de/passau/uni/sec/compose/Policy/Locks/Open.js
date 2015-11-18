"use strict";

if(global && typeof print !== "function") {
    var PolicyConfig = require("./../PolicyConfig.js");
    var Lock = require(PolicyConfig.rootDir + "./../Lock.js");
    var system = require(PolicyConfig.rootDir + "./../system.js");
}

var OpenLock  = function(lock) {
    // call the super class constructor
    OpenLock.super_.call(this, lock);
}

system.inherits(OpenLock, Lock);

OpenLock.prototype.copy = function() {
    var c = new Closed();
    return c;
}

OpenLock.prototype.isOpen = function(context) {
    return { open : true, conditional : false }
}

OpenLock.prototype.lub = function(lock) {
    return lock;
}

if(global && typeof print !== "function")
    module.exports = OpenLock;
