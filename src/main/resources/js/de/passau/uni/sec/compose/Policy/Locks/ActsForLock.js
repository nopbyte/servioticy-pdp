/**
 * Copyright 2015 Daniel Schreckling
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

"use strict";

if(global && typeof print !== "function") {
    var PolicyConfig = require("./../PolicyConfig.js");
    var Lock = require(PolicyConfig.rootDir + "./../Lock.js");
    var system = require(PolicyConfig.rootDir + "./../system.js");
}

var ActsForLock = function(lock) {
    // call the super class constructor
    ActsForLock.super_.call(this, lock);
}

Lock.registerLock("actsFor", ActsForLock);

system.inherits(ActsForLock, Lock);

ActsForLock.prototype.copy = function() {
    var c = new ActsForLock(this);
    return c;
}

ActsForLock.prototype.handleUser = function(context) {
    return { result : false, conditional : false };
};

ActsForLock.prototype.handleSO = function(context) {
    if(context.subject.data.owner_id == this.args[0])
        return { result : true, conditional : false };
    else
        return { result : false, conditional : false };
};

ActsForLock.prototype.handleSU = function(context) {
    console.log("ActsForLock.prototype.handleSU: "+context.object.data.owner_id);
    if(context.object.data.owner_id == this.args[0])
        return { result : true, conditional : false };
    else
        return { result : false, conditional : false };
};

ActsForLock.prototype.handleMsg = function(context) {
    if(context) {
        var open = context.getLockState(this, context.object);
        /* if(context.object.data)
            console.log("check lock for node: "+context.object.data.id);
        console.log("is already open?: "+open); */
        return { result : open, conditional : false };
    } else {
        return { result : false, conditional : false };
    }
};

ActsForLock.prototype.handleNode = function(context) {
    if(context.subject.data.ownerId == this.args[0])
        return { result : true, conditional : false };
    else
        return { result : false, conditional : false };
};

ActsForLock.prototype.handleApp = function(context) {
    return { open : false, conditional : false };
};

ActsForLock.prototype.isOpen = function(context) {
    // console.log("ActsForLock.prototype.isOpen");
    if(context) {
		if(context.subject) {
            if(!context.static) { // when evaluation dynamically
                switch(context.subject.type) {
                case "node" : { 
                    return this.handleNode(context);
                    break; 
                }
                case "user" : { 
                    return this.handleUser(context);
                    break;
                }
                case "app" : { 
                    return this.handleApp(context);
                    break;
                }
                case "so" : { 
                    return this.handleSO(context);
                    break;
                }
                case "su" : { 
                    return this.handleSU(context);
                    break;
                }
                case "msg" : {
                    return this.handleMsg(context);
                    break;
                }
                }
            } else { // when evaluating statically
                if(context.subject.ownerId) {
                    if(context.subject.data.ownerId == this.args[0])
		                return { result : true, conditional : false };
                    else
                        return { result : false, conditional : false };
                } else {
                    return { result : true, conditional : true, locks : this };
                }
            }
        } else {
            throw new Error("ActsForLock: Require context.subject information to evaluate lock");
        }
    } else {
        throw new Error("ActsForLock: Require context information to evaluate lock.");
    }
};

ActsForLock.prototype.lub = function(lock) {
    if(this.eq(lock))
        return Lock.createLock(this);
     else {
        if(this.path == lock.path)
            return Lock.closedLock();
        else
            return null;
    }
};

if(global && typeof print !== "function")
    module.exports = ActsForLock;
